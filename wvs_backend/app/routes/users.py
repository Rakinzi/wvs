import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, set_access_cookies, unset_jwt_cookies
from app.auth import get_current_user
from app.models import User
from app.schemas import (
    AuthLoginPayload,
    AuthRegisterPayload,
    ForgotPasswordPayload,
    ResetPasswordPayload,
)
from app import db, limiter
from pydantic import ValidationError
from app.utils.time_utils import utc_now

bp = Blueprint('users', __name__)


def _validation_error_payload(exc: ValidationError) -> dict:
    try:
        errors = exc.errors(include_context=False)
    except TypeError:
        errors = exc.errors()
        for error in errors:
            if "ctx" in error:
                error["ctx"] = {key: str(value) for key, value in error["ctx"].items()}

    first_error = errors[0]["msg"] if errors else "Invalid request payload"
    return {"error": first_error, "errors": errors}


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _build_reset_link(token: str) -> str:
    base_url = current_app.config["FRONTEND_BASE_URL"].rstrip("/")
    return f"{base_url}/reset-password?token={token}"


def _build_reset_email_html(username: str, reset_link: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F1F5F9;font-family:'Inter',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F1F5F9;padding:40px 16px;">
    <tr><td align="center">
      <table width="100%" style="max-width:520px;background:#FFFFFF;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <!-- Header -->
        <tr>
          <td style="background:#0F172A;padding:32px 40px;text-align:center;">
            <span style="display:inline-block;background:#3B82F6;border-radius:8px;padding:8px 14px;">
              <span style="color:#FFFFFF;font-size:18px;font-weight:700;letter-spacing:0.5px;">&#128737; WebVulnScanner</span>
            </span>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:40px 40px 32px;">
            <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#0F172A;">Reset your password</h1>
            <p style="margin:0 0 24px;font-size:15px;color:#64748B;line-height:1.6;">
              Hi <strong style="color:#0F172A;">{username}</strong>, we received a request to reset the password for your account.
            </p>
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td align="center" style="padding:8px 0 28px;">
                <a href="{reset_link}"
                   style="display:inline-block;background:#3B82F6;color:#FFFFFF;text-decoration:none;
                          font-size:15px;font-weight:600;padding:14px 32px;border-radius:8px;
                          letter-spacing:0.2px;">
                  Reset Password
                </a>
              </td></tr>
            </table>
            <p style="margin:0 0 12px;font-size:13px;color:#94A3B8;line-height:1.6;">
              Or copy this link into your browser:
            </p>
            <p style="margin:0 0 24px;font-size:12px;word-break:break-all;
                      background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;
                      padding:10px 14px;color:#475569;">
              {reset_link}
            </p>
            <hr style="border:none;border-top:1px solid #E2E8F0;margin:0 0 24px;">
            <p style="margin:0;font-size:13px;color:#94A3B8;line-height:1.6;">
              This link expires in 30 minutes. If you didn't request a password reset, you can safely ignore this email — your password won't change.
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#F8FAFC;border-top:1px solid #E2E8F0;padding:20px 40px;text-align:center;">
            <p style="margin:0;font-size:12px;color:#94A3B8;">
              &copy; 2026 WebVulnScanner &nbsp;&middot;&nbsp; You're receiving this because a reset was requested for your account.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _send_reset_email(email: str, username: str, reset_link: str) -> None:
    smtp_user = current_app.config.get("SMTP_USER")
    smtp_password = current_app.config.get("SMTP_PASSWORD")
    smtp_from = current_app.config.get("SMTP_FROM_EMAIL")

    if not smtp_user or not smtp_password or not smtp_from:
        raise RuntimeError("SMTP credentials are not configured")

    message = EmailMessage()
    message["Subject"] = "Reset your WebVulnScanner password"
    message["From"] = smtp_from
    message["To"] = email
    message.set_content(
        "\n".join(
            [
                f"Hello {username},",
                "",
                "We received a request to reset your WebVulnScanner password.",
                f"Use this link to choose a new password: {reset_link}",
                "",
                "This link expires in 30 minutes. If you did not request this reset, you can ignore this email.",
            ]
        )
    )
    message.add_alternative(_build_reset_email_html(username, reset_link), subtype="html")

    with smtplib.SMTP(current_app.config["SMTP_HOST"], current_app.config["SMTP_PORT"]) as smtp:
        smtp.ehlo()
        if current_app.config["SMTP_USE_TLS"]:
            smtp.starttls()
            smtp.ehlo()
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)

def _build_verify_link(token: str) -> str:
    base_url = current_app.config["FRONTEND_BASE_URL"].rstrip("/")
    return f"{base_url}/verify-email?token={token}"


def _send_verification_email(email: str, username: str, verify_link: str) -> None:
    smtp_user = current_app.config.get("SMTP_USER")
    smtp_password = current_app.config.get("SMTP_PASSWORD")
    smtp_from = current_app.config.get("SMTP_FROM_EMAIL")

    if not smtp_user or not smtp_password or not smtp_from:
        raise RuntimeError("SMTP credentials are not configured")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F1F5F9;font-family:'Inter',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F1F5F9;padding:40px 16px;">
    <tr><td align="center">
      <table width="100%" style="max-width:520px;background:#FFFFFF;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
        <tr><td style="background:#0F172A;padding:32px 40px;text-align:center;">
          <span style="display:inline-block;background:#3B82F6;border-radius:8px;padding:8px 14px;">
            <span style="color:#FFFFFF;font-size:18px;font-weight:700;letter-spacing:0.5px;">WebVulnScanner</span>
          </span>
        </td></tr>
        <tr><td style="padding:40px 40px 32px;">
          <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#0F172A;">Verify your email</h1>
          <p style="margin:0 0 24px;font-size:15px;color:#64748B;line-height:1.6;">
            Hi <strong style="color:#0F172A;">{username}</strong>, confirm your email address to activate your account.
          </p>
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td align="center" style="padding:8px 0 28px;">
              <a href="{verify_link}" style="display:inline-block;background:#3B82F6;color:#FFFFFF;text-decoration:none;font-size:15px;font-weight:600;padding:14px 32px;border-radius:8px;">
                Verify Email
              </a>
            </td></tr>
          </table>
          <p style="margin:0 0 12px;font-size:13px;color:#94A3B8;">Or copy this link into your browser:</p>
          <p style="margin:0 0 24px;font-size:12px;word-break:break-all;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:10px 14px;color:#475569;">
            {verify_link}
          </p>
          <hr style="border:none;border-top:1px solid #E2E8F0;margin:0 0 24px;">
          <p style="margin:0;font-size:13px;color:#94A3B8;">This link expires in 24 hours. If you did not create this account you can ignore this email.</p>
        </td></tr>
        <tr><td style="background:#F8FAFC;border-top:1px solid #E2E8F0;padding:20px 40px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94A3B8;">&copy; 2026 WebVulnScanner</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    message = EmailMessage()
    message["Subject"] = "Verify your WebVulnScanner email address"
    message["From"] = smtp_from
    message["To"] = email
    message.set_content(f"Hi {username},\n\nVerify your email: {verify_link}\n\nThis link expires in 24 hours.")
    message.add_alternative(html, subtype="html")

    with smtplib.SMTP(current_app.config["SMTP_HOST"], current_app.config["SMTP_PORT"]) as smtp:
        smtp.ehlo()
        if current_app.config["SMTP_USE_TLS"]:
            smtp.starttls()
            smtp.ehlo()
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)


@bp.route('/verify-email/confirm', methods=['POST'])
@limiter.limit("20 per hour")
def confirm_email_verification():
    data = request.get_json(silent=True) or {}
    token = (data.get('token') or '').strip()
    if not token:
        return jsonify({'error': 'Verification token is required'}), 400

    token_hash = _hash_reset_token(token)
    user = User.query.filter_by(verification_token_hash=token_hash).first()
    if (
        not user
        or not user.verification_token_expires_at
        or user.verification_token_expires_at < utc_now()
    ):
        return jsonify({'error': 'Invalid or expired verification link'}), 400

    user.email_verified = True
    user.verification_token_hash = None
    user.verification_token_expires_at = None
    db.session.commit()
    return jsonify({'message': 'Email verified successfully'}), 200


@bp.route('/verify-email/resend', methods=['POST'])
@jwt_required()
@limiter.limit("3 per hour")
def resend_verification_email():
    user = get_current_user()
    if user.email_verified:
        return jsonify({'message': 'Email already verified'}), 200

    raw_token = secrets.token_urlsafe(32)
    user.verification_token_hash = _hash_reset_token(raw_token)
    user.verification_token_expires_at = utc_now() + timedelta(hours=24)
    db.session.commit()

    try:
        _send_verification_email(user.email, user.username, _build_verify_link(raw_token))
    except Exception:
        current_app.logger.exception("Failed to send verification email")
        return jsonify({'error': 'Could not send verification email'}), 500

    return jsonify({'message': 'Verification email sent'}), 200


@bp.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    try:
        payload = AuthRegisterPayload.model_validate(request.get_json(silent=True) or {})
        username = payload.username
        password = payload.password
        email = payload.email.lower()
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email address already registered'}), 400
            
        raw_token = secrets.token_urlsafe(32)
        user = User(username=username, email=email)
        user.set_password(password)
        user.verification_token_hash = _hash_reset_token(raw_token)
        user.verification_token_expires_at = utc_now() + timedelta(hours=24)

        db.session.add(user)
        db.session.commit()

        try:
            _send_verification_email(email, username, _build_verify_link(raw_token))
        except Exception:
            current_app.logger.warning("Could not send verification email to %s", email)

        return jsonify({'message': 'Account created. Check your email to verify your address.'}), 201
    except ValidationError as exc:
        return jsonify(_validation_error_payload(exc)), 400
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to register user")
        return jsonify({'error': 'Unable to create account at this time'}), 500

@bp.route('/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    try:
        payload = AuthLoginPayload.model_validate(request.get_json(silent=True) or {})
        identifier = payload.identifier.strip()

        if '@' in identifier:
            user = User.query.filter_by(email=identifier.lower()).first()
        else:
            user = User.query.filter_by(username=identifier).first()

        if not user or not user.check_password(payload.password):
            return jsonify({'error': 'Invalid credentials'}), 401

        expires_in = int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds())
        access_token = create_access_token(identity=str(user.id))
        response = jsonify({
            'username': user.username,
            'user_id': user.id,
            'is_admin': user.is_admin,
            'expires_in': expires_in,
        })
        set_access_cookies(response, access_token)
        return response, 200
    except ValidationError as exc:
        return jsonify(_validation_error_payload(exc)), 400
    except Exception:
        current_app.logger.exception("Failed to authenticate user")
        return jsonify({'error': 'Unable to complete sign in at this time'}), 500


@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({'message': 'Signed out successfully'})
    unset_jwt_cookies(response)
    return response, 200


@bp.route('/forgot-password', methods=['POST'])
@limiter.limit("5 per hour")
def forgot_password():
    try:
        payload = ForgotPasswordPayload.model_validate(request.get_json(silent=True) or {})
        user = User.query.filter_by(email=payload.email.lower()).first()

        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token_hash = _hash_reset_token(token)
            user.reset_requested_at = utc_now()
            user.reset_token_expires_at = user.reset_requested_at + timedelta(
                minutes=current_app.config["RESET_PASSWORD_TOKEN_TTL_MINUTES"]
            )
            db.session.commit()
            try:
                _send_reset_email(user.email, user.username, _build_reset_link(token))
            except Exception:
                current_app.logger.exception("Failed to send password reset email")
                return jsonify({'error': 'Could not send reset email. Please try again later.'}), 503

        return jsonify(
            {
                'message': 'If the account exists, a password reset link will be sent shortly.'
            }
        ), 200
    except ValidationError as exc:
        return jsonify(_validation_error_payload(exc)), 400
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to process forgot password request")
        return jsonify({'error': 'Unable to process password reset request'}), 500


@bp.route('/reset-password', methods=['POST'])
@limiter.limit("10 per hour")
def reset_password():
    try:
        payload = ResetPasswordPayload.model_validate(request.get_json(silent=True) or {})
        token_hash = _hash_reset_token(payload.token)
        user = User.query.filter_by(reset_token_hash=token_hash).first()

        if (
            not user
            or not user.reset_token_expires_at
            or user.reset_token_expires_at < utc_now()
        ):
            return jsonify({'error': 'This password reset link is invalid or has expired'}), 400

        user.set_password(payload.password)
        user.reset_token_hash = None
        user.reset_token_expires_at = None
        user.reset_requested_at = None
        db.session.commit()

        return jsonify({'message': 'Password reset successfully'}), 200
    except ValidationError as exc:
        return jsonify(_validation_error_payload(exc)), 400
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to reset password")
        return jsonify({'error': 'Unable to reset password at this time'}), 500

@bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': user.username,
        'email': user.email,
        'created_on': user.created_on.isoformat(),
        'email_verified': user.email_verified,
        'is_admin': user.is_admin,
    }), 200

@bp.route('/profile', methods=['PATCH'])
@jwt_required()
@limiter.limit("10 per hour")
def update_profile():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if username and username != user.username:
        if len(username) < 3 or len(username) > 50:
            return jsonify({'error': 'Username must be between 3 and 50 characters'}), 400
        if User.query.filter(User.username == username, User.id != user.id).first():
            return jsonify({'error': 'Username already taken'}), 400
        user.username = username

    if new_password:
        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters'}), 400
        if not current_password or not user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400
        user.set_password(new_password)

    try:
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully', 'username': user.username}), 200
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to update profile")
        return jsonify({'error': 'Unable to update profile'}), 500


@bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    users = User.query.all()
    users_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'created_on': user.created_on.isoformat()
    } for user in users]
    
    return jsonify(users_data), 200
