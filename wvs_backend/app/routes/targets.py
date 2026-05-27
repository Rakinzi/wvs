from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import jwt_required
from pydantic import ValidationError

from app import db, limiter
from app.auth import get_current_user
from app.models import VerifiedTarget
from app.schemas import VerifiedTargetCreatePayload
from app.utils.scan_helpers import (
    extract_target_hostname,
    extract_target_origin,
    normalize_target_url,
    validate_target_redirect,
)
from app.utils.time_utils import utc_now


bp = Blueprint("targets", __name__)

_META_NAME = "wvs-site-verification"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _generate_token() -> str:
    return secrets.token_urlsafe(24)


def _build_instructions(method: str, token: str, origin: str) -> dict:
    if method == "well_known_file":
        return {
            "method": "well_known_file",
            "path": "/.well-known/wvs-site-verification.txt",
            "content": token,
            "verification_url": f"{origin}/.well-known/wvs-site-verification.txt",
        }

    return {
        "method": "meta_tag",
        "tag": f'<meta name="{_META_NAME}" content="{token}" />',
        "placement": "Add the meta tag inside the <head> element of the submitted site.",
        "verification_url": origin,
    }


def _serialize_target(target: VerifiedTarget) -> dict:
    data = target.to_dict()
    data["requires_verification_for_scans"] = current_app.config.get("REQUIRE_VERIFIED_TARGETS", False)
    # Include live instructions whenever a token is stored and not yet verified
    if target.verification_token and target.verification_status != "verified":
        data["instructions"] = _build_instructions(
            target.verification_method,
            target.verification_token,
            extract_target_origin(target.target_url),
        )
    else:
        data["instructions"] = None
    return data


def _fetch_verification_response(url: str, expected_hostname: str) -> tuple[str, str]:
    timeout = current_app.config["TARGET_VERIFICATION_TIMEOUT_SECONDS"]
    max_bytes = current_app.config["TARGET_VERIFICATION_MAX_BYTES"]
    max_redirects = current_app.config["TARGET_VERIFICATION_MAX_REDIRECTS"]
    current_url = validate_target_redirect(url, expected_hostname)

    for redirect_count in range(max_redirects + 1):
        response = requests.get(
            current_url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "WVS-TargetVerification/1.0"},
        )
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
    verification_url = f"{origin}/.well-known/wvs-site-verification.txt"
    body, _ = _fetch_verification_response(verification_url, target.normalized_domain)
    if body.strip() != raw_token:
        raise ValueError("Verification token did not match")


def _verification_expiry():
    return utc_now() + timedelta(hours=current_app.config["TARGET_VERIFICATION_TOKEN_TTL_HOURS"])


@bp.route("/targets", methods=["POST"])
@jwt_required()
@limiter.limit("20 per hour")
def create_target():
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "User not found"}), 404

        payload = VerifiedTargetCreatePayload.model_validate(request.get_json(silent=True) or {})
        target_url = normalize_target_url(payload.target_url)
        normalized_domain = extract_target_hostname(target_url)
        raw_token = _generate_token()

        target = VerifiedTarget.query.filter_by(
            user_id=user.id,
            normalized_domain=normalized_domain,
        ).first()
        status_code = 200
        if not target:
            target = VerifiedTarget(
                user_id=user.id,
                target_url=target_url,
                normalized_domain=normalized_domain,
                verification_method=payload.verification_method,
                verification_token_hash=_hash_token(raw_token),
                verification_token=raw_token,
                verification_status="pending",
                token_expires_at=_verification_expiry(),
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

        return jsonify(
            {
                "status": "success",
                "target": _serialize_target(target),
                "verification_token": raw_token,
                "instructions": _build_instructions(
                    target.verification_method,
                    raw_token,
                    extract_target_origin(target.target_url),
                ),
            }
        ), status_code
    except (ValidationError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to create verification target")
        return jsonify({"error": "Unable to create verification target"}), 500


@bp.route("/targets", methods=["GET"])
@jwt_required()
def list_targets():
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    targets = VerifiedTarget.query.filter_by(user_id=user.id).order_by(VerifiedTarget.created_at.desc()).all()
    return jsonify({"status": "success", "targets": [_serialize_target(target) for target in targets]}), 200


@bp.route("/targets/<string:target_id>", methods=["GET"])
@jwt_required()
def get_target(target_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    target = VerifiedTarget.query.filter_by(public_id=target_id).first_or_404()
    if target.user_id != user.id and not user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify({"status": "success", "target": _serialize_target(target)}), 200


@bp.route("/targets/<string:target_id>/verification-token", methods=["POST"])
@jwt_required()
@limiter.limit("10 per hour")
def regenerate_verification_token(target_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    target = VerifiedTarget.query.filter_by(public_id=target_id).first_or_404()
    if target.user_id != user.id and not user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    raw_token = _generate_token()
    target.verification_token_hash = _hash_token(raw_token)
    target.verification_token = raw_token
    target.verification_status = "pending"
    target.verified_at = None
    target.token_expires_at = _verification_expiry()
    db.session.commit()

    return jsonify(
        {
            "status": "success",
            "target": _serialize_target(target),
            "verification_token": raw_token,
            "instructions": _build_instructions(
                target.verification_method,
                raw_token,
                extract_target_origin(target.target_url),
            ),
        }
    ), 200


@bp.route("/targets/<string:target_id>/verify", methods=["POST"])
@jwt_required()
@limiter.limit("20 per hour")
def verify_target(target_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    target = VerifiedTarget.query.filter_by(public_id=target_id).first_or_404()
    if target.user_id != user.id and not user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    if target.token_expires_at < utc_now():
        target.verification_status = "expired"
        db.session.commit()
        return jsonify({"error": "Verification token has expired"}), 400

    raw_token = (request.get_json(silent=True) or {}).get("token", "").strip()
    if not raw_token:
        return jsonify({"error": "Verification token is required"}), 400
    if _hash_token(raw_token) != target.verification_token_hash:
        target.verification_status = "failed"
        db.session.commit()
        return jsonify({"error": "Verification token did not match"}), 400

    try:
        if target.verification_method == "well_known_file":
            _verify_well_known_file(target, raw_token)
        else:
            _verify_meta_tag(target, raw_token)
    except requests.RequestException:
        current_app.logger.exception("Verification request failed")
        return jsonify({"error": "Could not fetch target for verification"}), 502
    except ValueError as exc:
        target.verification_status = "failed"
        db.session.commit()
        return jsonify({"error": str(exc)}), 400

    target.verification_status = "verified"
    target.verified_at = utc_now()
    target.verification_token = None
    db.session.commit()

    return jsonify({"status": "success", "target": _serialize_target(target)}), 200


@bp.route("/targets/<string:target_id>", methods=["DELETE"])
@jwt_required()
def delete_target(target_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    target = VerifiedTarget.query.filter_by(public_id=target_id).first_or_404()
    if target.user_id != user.id and not user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    db.session.delete(target)
    db.session.commit()
    return jsonify({"status": "success", "message": "Target deleted"}), 200
