from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Annotated
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from app import db
from app.auth import current_user
from app.models import User, VerifiedTarget
from app.schemas import VerifiedTargetCreatePayload
from app.settings import settings
from app.utils.scan_helpers import extract_target_hostname, extract_target_origin, normalize_target_url, validate_target_redirect
from app.utils.time_utils import utc_now

router = APIRouter()

_META_NAME = "wvs-site-verification"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _generate_token() -> str:
    return secrets.token_urlsafe(24)


def _build_instructions(method: str, token: str, origin: str) -> dict:
    if method == "well_known_file":
        return {"method": "well_known_file", "path": "/.well-known/wvs-site-verification.txt",
                "content": token, "verification_url": f"{origin}/.well-known/wvs-site-verification.txt"}
    return {"method": "meta_tag", "tag": f'<meta name="{_META_NAME}" content="{token}" />',
            "placement": "Add the meta tag inside the <head> element.", "verification_url": origin}


def _serialize_target(target: VerifiedTarget) -> dict:
    data = target.to_dict()
    data.pop("verification_token", None)
    data["requires_verification_for_scans"] = settings.require_verified_targets
    if target.verification_token and target.verification_status != "verified":
        data["instructions"] = _build_instructions(target.verification_method, target.verification_token, extract_target_origin(target.target_url))
    else:
        data["instructions"] = None
    return data


def _fetch_verification_response(url: str, expected_hostname: str) -> tuple[str, str]:
    timeout = settings.target_verification_timeout_seconds
    max_bytes = settings.target_verification_max_bytes
    max_redirects = settings.target_verification_max_redirects
    current_url = validate_target_redirect(url, expected_hostname)

    for redirect_count in range(max_redirects + 1):
        response = requests.get(current_url, timeout=timeout, allow_redirects=False, stream=True, headers={"User-Agent": "WVS-TargetVerification/1.0"})
        if response.is_redirect or response.is_permanent_redirect:
            if redirect_count >= max_redirects:
                response.close()
                raise ValueError("Too many redirects during verification")
            location = response.headers.get("Location")
            if not location:
                response.close()
                raise ValueError("Redirect response did not include a Location header")
            current_url = validate_target_redirect(urljoin(current_url, location), expected_hostname)
            response.close()
            continue
        declared_length = response.headers.get("Content-Length")
        if declared_length and int(declared_length) > max_bytes:
            response.close()
            raise ValueError("Verification response exceeded allowed size")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("Verification response exceeded allowed size")
            chunks.append(chunk)
        response.close()
        return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace"), current_url

    raise ValueError("Too many redirects during verification")


def _verify_meta_tag(target: VerifiedTarget, raw_token: str) -> None:
    origin = extract_target_origin(target.target_url)
    body, _ = _fetch_verification_response(origin, target.normalized_domain)
    soup = BeautifulSoup(body, "html.parser")
    meta = soup.find("meta", attrs={"name": _META_NAME})
    if not meta:
        raise ValueError("Verification meta tag was not found")
    if (meta.get("content") or "").strip() != raw_token:
        raise ValueError("Verification token did not match")


def _verify_well_known_file(target: VerifiedTarget, raw_token: str) -> None:
    origin = extract_target_origin(target.target_url)
    body, _ = _fetch_verification_response(f"{origin}/.well-known/wvs-site-verification.txt", target.normalized_domain)
    if body.strip() != raw_token:
        raise ValueError("Verification token did not match")


def _verification_expiry():
    return utc_now() + timedelta(hours=settings.target_verification_token_ttl_hours)


@router.post("/targets", status_code=201)
async def create_target(request: Request, user: Annotated[User, Depends(current_user)]):
    try:
        data = await request.json()
        payload = VerifiedTargetCreatePayload.model_validate(data)
        target_url = normalize_target_url(payload.target_url)
        normalized_domain = extract_target_hostname(target_url)
        raw_token = _generate_token()

        target = VerifiedTarget.query.filter_by(user_id=user.id, normalized_domain=normalized_domain).first()
        status_code = 200
        if not target:
            target = VerifiedTarget(
                user_id=user.id, target_url=target_url, normalized_domain=normalized_domain,
                verification_method=payload.verification_method, verification_token_hash=_hash_token(raw_token),
                verification_token=raw_token, verification_status="pending", token_expires_at=_verification_expiry(),
            )
            db.session.add(target)
            status_code = 201
        else:
            target.target_url = target_url
            target.verification_method = payload.verification_method
            target.verification_token_hash = _hash_token(raw_token)
            target.verification_token = raw_token
            target.verification_status = "pending"
            target.verified_at = None
            target.token_expires_at = _verification_expiry()

        db.session.commit()
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=status_code,
            content={"status": "success", "target": _serialize_target(target), "verification_token": raw_token,
                     "instructions": _build_instructions(target.verification_method, raw_token, extract_target_origin(target.target_url))},
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        db.session.rollback()
        raise HTTPException(500, "Unable to create verification target")


@router.get("/targets")
def list_targets(user: Annotated[User, Depends(current_user)]):
    targets = VerifiedTarget.query.filter_by(user_id=user.id).order_by(VerifiedTarget.created_at.desc()).all()
    return {"status": "success", "targets": [_serialize_target(t) for t in targets]}


@router.get("/targets/{target_id}")
def get_target(target_id: str, user: Annotated[User, Depends(current_user)]):
    target = VerifiedTarget.query.filter_by(public_id=target_id).first_or_404()
    if target.user_id != user.id and not user.is_admin:
        raise HTTPException(403, "Unauthorized")
    return {"status": "success", "target": _serialize_target(target)}


@router.post("/targets/{target_id}/verification-token")
def regenerate_verification_token(target_id: str, user: Annotated[User, Depends(current_user)]):
    target = VerifiedTarget.query.filter_by(public_id=target_id).first_or_404()
    if target.user_id != user.id and not user.is_admin:
        raise HTTPException(403, "Unauthorized")
    raw_token = _generate_token()
    target.verification_token_hash = _hash_token(raw_token)
    target.verification_token = raw_token
    target.verification_status = "pending"
    target.verified_at = None
    target.token_expires_at = _verification_expiry()
    db.session.commit()
    return {"status": "success", "target": _serialize_target(target), "verification_token": raw_token,
            "instructions": _build_instructions(target.verification_method, raw_token, extract_target_origin(target.target_url))}


@router.post("/targets/{target_id}/verify")
async def verify_target(target_id: str, request: Request, user: Annotated[User, Depends(current_user)]):
    target = VerifiedTarget.query.filter_by(public_id=target_id).first_or_404()
    if target.user_id != user.id and not user.is_admin:
        raise HTTPException(403, "Unauthorized")
    if target.token_expires_at < utc_now():
        target.verification_status = "expired"
        db.session.commit()
        raise HTTPException(400, "Verification token has expired")

    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    raw_token = (data.get("token") or "").strip()
    if not raw_token:
        raise HTTPException(400, "Verification token is required")
    if _hash_token(raw_token) != target.verification_token_hash:
        target.verification_status = "failed"
        db.session.commit()
        raise HTTPException(400, "Verification token did not match")

    try:
        if target.verification_method == "well_known_file":
            _verify_well_known_file(target, raw_token)
        else:
            _verify_meta_tag(target, raw_token)
    except requests.RequestException:
        raise HTTPException(502, "Could not fetch target for verification")
    except ValueError as exc:
        target.verification_status = "failed"
        db.session.commit()
        raise HTTPException(400, str(exc))

    target.verification_status = "verified"
    target.verified_at = utc_now()
    target.verification_token = None
    db.session.commit()
    return {"status": "success", "target": _serialize_target(target)}


@router.delete("/targets/{target_id}")
def delete_target(target_id: str, user: Annotated[User, Depends(current_user)]):
    target = VerifiedTarget.query.filter_by(public_id=target_id).first_or_404()
    if target.user_id != user.id and not user.is_admin:
        raise HTTPException(403, "Unauthorized")
    db.session.delete(target)
    db.session.commit()
    return {"status": "success", "message": "Target deleted"}
