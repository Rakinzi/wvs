from __future__ import annotations

import hashlib
import secrets
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import ValidationError

from app import db
from app.auth import current_user, require_admin, get_user_from_cookie
from app.models import User, ROLES, ROLE_SCAN_LIMITS, ROLE_MONITOR_LIMITS
from app.schemas import AuthLoginPayload, AuthRegisterPayload, ForgotPasswordPayload, ResetPasswordPayload
from app.settings import settings
from app.utils.time_utils import utc_now

import jwt as pyjwt
from datetime import datetime, timezone

router = APIRouter()


# ── helpers ─────────────────────────────────────────────────────────────────

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validation_message(exc: ValidationError) -> str:
    messages = []
    for issue in exc.errors():
        field = ".".join(str(part) for part in issue.get("loc", []) if part != "body")
        message = issue.get("msg", "Invalid value")
        if message.startswith("Value error, "):
            message = message.removeprefix("Value error, ")
        messages.append(f"{field}: {message}" if field else message)
    return "; ".join(messages) or "The submitted information is invalid"


def _build_reset_link(token: str) -> str:
    return f"{settings.frontend_base_url.rstrip('/')}/reset-password?token={token}"


def _build_verify_link(token: str) -> str:
    return f"{settings.frontend_base_url.rstrip('/')}/verify-email?token={token}"


def _send_reset_email(email: str, username: str, reset_link: str) -> None:
    smtp_user = settings.smtp_user
    smtp_password = settings.smtp_password
    smtp_from = settings.smtp_from_email
    if not smtp_user or not smtp_password or not smtp_from:
        raise RuntimeError("SMTP credentials are not configured")
    html = _build_reset_email_html(username, reset_link)
    msg = EmailMessage()
    msg["Subject"] = "Reset your LaunchGuard password"
    msg["From"] = smtp_from
    msg["To"] = email
    msg.set_content(f"Hi {username},\n\nReset your password: {reset_link}\n\nExpires in 30 minutes.")
    msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as s:
        s.ehlo()
        if settings.smtp_use_tls:
            s.starttls(); s.ehlo()
        s.login(smtp_user, smtp_password)
        s.send_message(msg)


def _build_reset_email_html(username: str, reset_link: str) -> str:
    return f"""<!DOCTYPE html><html lang="en"><body style="font-family:Arial,sans-serif;background:#F1F5F9;padding:40px 16px;">
<table width="100%" style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:40px;">
<tr><td><h1 style="color:#0F172A">Reset your password</h1>
<p>Hi <strong>{username}</strong>, click the button below to reset your password.</p>
<a href="{reset_link}" style="display:inline-block;background:#3B82F6;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;">Reset Password</a>
<p style="color:#94A3B8;font-size:13px;margin-top:24px">Expires in 30 minutes. If you didn't request this, ignore this email.</p>
</td></tr></table></body></html>"""


def _send_verification_email(email: str, username: str, verify_link: str) -> None:
    smtp_user = settings.smtp_user
    smtp_password = settings.smtp_password
    smtp_from = settings.smtp_from_email
    if not smtp_user or not smtp_password or not smtp_from:
        raise RuntimeError("SMTP credentials are not configured")
    html = f"""<!DOCTYPE html><html lang="en"><body style="font-family:Arial,sans-serif;background:#F1F5F9;padding:40px 16px;">
<table width="100%" style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:40px;">
<tr><td><h1 style="color:#0F172A">Verify your email</h1>
<p>Hi <strong>{username}</strong>, confirm your email to activate your account.</p>
<a href="{verify_link}" style="display:inline-block;background:#3B82F6;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;">Verify Email</a>
<p style="color:#94A3B8;font-size:13px;margin-top:24px">Expires in 24 hours.</p>
</td></tr></table></body></html>"""
    msg = EmailMessage()
    msg["Subject"] = "Verify your LaunchGuard email"
    msg["From"] = smtp_from
    msg["To"] = email
    msg.set_content(f"Hi {username},\n\nVerify your email: {verify_link}\n\nExpires in 24 hours.")
    msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as s:
        s.ehlo()
        if settings.smtp_use_tls:
            s.starttls(); s.ehlo()
        s.login(smtp_user, smtp_password)
        s.send_message(msg)


def _create_access_token(user_id: int) -> tuple[str, int]:
    expires_in = 3600
    exp = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    token = pyjwt.encode(
        {"sub": str(user_id), "exp": exp},
        settings.effective_jwt_secret_key,
        algorithm="HS256",
    )
    return token, expires_in


def _set_auth_cookies(response: Response, token: str) -> None:
    secure = settings.app_env.lower() == "production"
    response.set_cookie(
        "access_token_cookie", token, httponly=True,
        samesite="lax", secure=secure, path="/",
    )
    response.set_cookie(
        "csrf_access_token", token[-32:],
        httponly=False, samesite="lax", secure=secure, path="/",
    )


def _unset_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token_cookie", path="/")
    response.delete_cookie("csrf_access_token", path="/")


def _user_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_admin": user.is_admin,
        "email_verified": user.email_verified,
        "created_on": user.created_on.isoformat() if user.created_on else None,
        "scan_limit": user.scan_limit,
        "monitor_limit": user.monitor_limit,
    }


# ── email verification ───────────────────────────────────────────────────────

@router.post("/verify-email/confirm")
async def confirm_email_verification(request: Request):
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    token = (data.get("token") or "").strip()
    if not token:
        raise HTTPException(400, "Verification token is required")
    token_hash = _hash_token(token)
    user = User.query.filter_by(verification_token_hash=token_hash).first()
    if not user or not user.verification_token_expires_at or user.verification_token_expires_at < utc_now():
        raise HTTPException(400, "Invalid or expired verification link")
    user.email_verified = True
    user.verification_token_hash = None
    user.verification_token_expires_at = None
    db.session.commit()
    return {"message": "Email verified successfully"}


@router.post("/verify-email/resend", status_code=200)
def resend_verification_email(user: Annotated[User, Depends(current_user)]):
    if user.email_verified:
        return {"message": "Email already verified"}
    raw_token = secrets.token_urlsafe(32)
    user.verification_token_hash = _hash_token(raw_token)
    user.verification_token_expires_at = utc_now() + timedelta(hours=24)
    db.session.commit()
    try:
        _send_verification_email(user.email, user.username, _build_verify_link(raw_token))
    except Exception:
        raise HTTPException(500, "Could not send verification email")
    return {"message": "Verification email sent"}


# ── register / login / logout ────────────────────────────────────────────────

@router.post("/register", status_code=201)
async def register(request: Request):
    try:
        data = await request.json()
        payload = AuthRegisterPayload.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(400, _validation_message(exc))
    except Exception:
        raise HTTPException(400, "Request body must be valid JSON")

    if User.query.filter_by(username=payload.username).first():
        raise HTTPException(400, "Username already taken")
    if User.query.filter_by(email=payload.email.lower()).first():
        raise HTTPException(400, "Email address already registered")

    raw_token = secrets.token_urlsafe(32)
    user = User(username=payload.username, email=payload.email.lower())
    user.set_password(payload.password)
    user.verification_token_hash = _hash_token(raw_token)
    user.verification_token_expires_at = utc_now() + timedelta(hours=24)
    db.session.add(user)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise HTTPException(500, "Unable to create account at this time")

    try:
        _send_verification_email(payload.email.lower(), payload.username, _build_verify_link(raw_token))
    except Exception:
        pass

    return {"message": "Account created. Check your email to verify your address."}


@router.post("/login")
async def login(request: Request, response: Response):
    try:
        data = await request.json()
        payload = AuthLoginPayload.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(400, _validation_message(exc))
    except Exception:
        raise HTTPException(400, "Request body must be valid JSON")

    identifier = payload.identifier.strip()
    user = (
        User.query.filter_by(email=identifier.lower()).first()
        if "@" in identifier
        else User.query.filter_by(username=identifier).first()
    )
    if not user or not user.check_password(payload.password):
        raise HTTPException(401, "Invalid credentials")

    token, expires_in = _create_access_token(user.id)
    _set_auth_cookies(response, token)
    return {
        "username": user.username,
        "user_id": user.id,
        "is_admin": user.is_admin,
        "role": user.role,
        "expires_in": expires_in,
    }


@router.post("/logout")
def logout(response: Response):
    _unset_auth_cookies(response)
    return {"message": "Signed out successfully"}


# ── password reset ───────────────────────────────────────────────────────────

@router.post("/forgot-password")
async def forgot_password(request: Request):
    try:
        data = await request.json()
        payload = ForgotPasswordPayload.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(400, _validation_message(exc))
    except Exception:
        raise HTTPException(400, "Request body must be valid JSON")

    user = User.query.filter_by(email=payload.email.lower()).first()
    if user:
        token = secrets.token_urlsafe(32)
        user.reset_token_hash = _hash_token(token)
        user.reset_requested_at = utc_now()
        user.reset_token_expires_at = user.reset_requested_at + timedelta(
            minutes=settings.reset_password_token_ttl_minutes
        )
        db.session.commit()
        try:
            _send_reset_email(user.email, user.username, _build_reset_link(token))
        except Exception:
            raise HTTPException(503, "Could not send reset email. Please try again later.")

    return {"message": "If the account exists, a password reset link will be sent shortly."}


@router.post("/reset-password")
async def reset_password(request: Request):
    try:
        data = await request.json()
        payload = ResetPasswordPayload.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(400, _validation_message(exc))
    except Exception:
        raise HTTPException(400, "Request body must be valid JSON")

    token_hash = _hash_token(payload.token)
    user = User.query.filter_by(reset_token_hash=token_hash).first()
    if not user or not user.reset_token_expires_at or user.reset_token_expires_at < utc_now():
        raise HTTPException(400, "This password reset link is invalid or has expired")

    user.set_password(payload.password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    user.reset_requested_at = None
    db.session.commit()
    return {"message": "Password reset successfully"}


# ── profile ──────────────────────────────────────────────────────────────────

@router.get("/profile")
def get_profile(user: Annotated[User, Depends(current_user)]):
    return {
        "username": user.username,
        "email": user.email,
        "created_on": user.created_on.isoformat() if user.created_on else None,
        "email_verified": user.email_verified,
        "is_admin": user.is_admin,
        "role": user.role,
        "scan_limit": user.scan_limit,
        "monitor_limit": user.monitor_limit,
    }


@router.patch("/profile")
async def update_profile(request: Request, user: Annotated[User, Depends(current_user)]):
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    username = (data.get("username") or "").strip()
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if username and username != user.username:
        if not (3 <= len(username) <= 50):
            raise HTTPException(400, "Username must be between 3 and 50 characters")
        if User.query.filter(User.username == username, User.id != user.id).first():
            raise HTTPException(400, "Username already taken")
        user.username = username

    if new_password:
        if len(new_password) < 8:
            raise HTTPException(400, "New password must be at least 8 characters")
        if not current_password or not user.check_password(current_password):
            raise HTTPException(400, "Current password is incorrect")
        user.set_password(new_password)

    try:
        db.session.commit()
        return {"message": "Profile updated successfully", "username": user.username}
    except Exception:
        db.session.rollback()
        raise HTTPException(500, "Unable to update profile")


# ── admin: user management ───────────────────────────────────────────────────

@router.get("/users")
def get_users(
    admin: Annotated[User, Depends(require_admin)],
    page: int = 1,
    per_page: int = 50,
    request: Request = None,
):
    per_page = min(per_page, 200)
    query = User.query.order_by(User.created_on.desc())
    total = query.count()
    users = query.offset((page - 1) * per_page).limit(per_page).all()
    return {"users": [_user_dict(u) for u in users], "total": total, "page": page, "per_page": per_page}


@router.patch("/admin/users/{user_id}/role")
async def set_user_role(
    user_id: int,
    request: Request,
    admin: Annotated[User, Depends(require_admin)],
):
    target = db.session.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == admin.id:
        raise HTTPException(400, "Cannot change your own role")
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    new_role = (data.get("role") or "").strip()
    if new_role not in ROLES:
        raise HTTPException(400, f"Invalid role. Must be one of: {', '.join(ROLES)}")
    target.role = new_role
    try:
        db.session.commit()
        return {"message": f"Role updated to {new_role}", "user": _user_dict(target)}
    except Exception:
        db.session.rollback()
        raise HTTPException(500, "Unable to update role")


@router.get("/admin/tiers")
def get_tier_config(admin: Annotated[User, Depends(require_admin)]):
    return {
        "tiers": [
            {
                "role": role,
                "scan_limit_per_hour": ROLE_SCAN_LIMITS.get(role),
                "monitor_limit": ROLE_MONITOR_LIMITS.get(role),
            }
            for role in ROLES
        ]
    }
