from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from pydantic import ValidationError
from urllib.parse import urlparse

from app import db
from app.auth import get_current_user
from app.models import UptimeMonitor, VerifiedTarget
from app.schemas import UptimeMonitorCreatePayload, UptimeMonitorUpdatePayload
from app.services.uptime import perform_uptime_check, serialize_monitor, validate_monitor_target


bp = Blueprint("uptime", __name__)


def _hostname_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _get_owned_monitor(monitor_id: str) -> UptimeMonitor:
    current_user = get_current_user()
    if not current_user:
        raise LookupError("User not found")

    monitor = UptimeMonitor.query.filter_by(public_id=monitor_id).first_or_404()
    if monitor.user_id != current_user.id and not current_user.is_admin:
        raise PermissionError("Unauthorized")
    return monitor


@bp.route("/uptime-monitors", methods=["GET"])
@jwt_required()
def list_uptime_monitors():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    monitors = UptimeMonitor.query.filter_by(user_id=current_user.id).order_by(UptimeMonitor.created_at.desc()).all()
    return jsonify({
        "status": "success",
        "monitors": [serialize_monitor(monitor) for monitor in monitors],
    }), 200


@bp.route("/uptime-monitors", methods=["POST"])
@jwt_required()
def create_uptime_monitor():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    try:
        payload = UptimeMonitorCreatePayload.model_validate(request.get_json(silent=True) or {})
    except (ValueError, ValidationError) as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    requested_target_url = payload.target_url
    verified_target = VerifiedTarget.query.filter_by(
        public_id=payload.verified_target_id,
        user_id=current_user.id,
        verification_status="verified",
    ).first()
    if not verified_target:
        return jsonify({
            "status": "error",
            "message": "Choose a verified target before adding an uptime monitor.",
        }), 403
    if verified_target.normalized_domain.lower() != _hostname_from_url(requested_target_url):
        return jsonify({
            "status": "error",
            "message": "The monitor URL must match the selected verified target.",
        }), 400
    try:
        target_url = validate_monitor_target(requested_target_url)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    monitor = UptimeMonitor(
        name=payload.name,
        target_url=target_url,
        check_interval_minutes=payload.check_interval_minutes,
        user_id=current_user.id,
    )
    db.session.add(monitor)
    db.session.commit()

    return jsonify({"status": "success", "monitor": serialize_monitor(monitor)}), 201


@bp.route("/uptime-monitors/<string:monitor_id>", methods=["GET"])
@jwt_required()
def get_uptime_monitor(monitor_id: str):
    try:
        monitor = _get_owned_monitor(monitor_id)
    except PermissionError:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    except LookupError:
        return jsonify({"status": "error", "message": "User not found"}), 404

    return jsonify({"status": "success", "monitor": serialize_monitor(monitor, include_checks=True)}), 200


@bp.route("/uptime-monitors/<string:monitor_id>", methods=["PATCH"])
@jwt_required()
def update_uptime_monitor(monitor_id: str):
    try:
        monitor = _get_owned_monitor(monitor_id)
    except PermissionError:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    except LookupError:
        return jsonify({"status": "error", "message": "User not found"}), 404

    try:
        payload = UptimeMonitorUpdatePayload.model_validate(request.get_json(silent=True) or {})
    except (ValueError, ValidationError) as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    if payload.name is not None:
        monitor.name = payload.name
    if payload.check_interval_minutes is not None:
        monitor.check_interval_minutes = payload.check_interval_minutes
    if payload.is_enabled is not None:
        monitor.is_enabled = payload.is_enabled
        if not payload.is_enabled:
            monitor.status = "paused"
        elif monitor.status == "paused":
            monitor.status = "pending"

    db.session.commit()
    return jsonify({"status": "success", "monitor": serialize_monitor(monitor)}), 200


@bp.route("/uptime-monitors/<string:monitor_id>", methods=["DELETE"])
@jwt_required()
def delete_uptime_monitor(monitor_id: str):
    try:
        monitor = _get_owned_monitor(monitor_id)
    except PermissionError:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    except LookupError:
        return jsonify({"status": "error", "message": "User not found"}), 404

    db.session.delete(monitor)
    db.session.commit()
    return jsonify({"status": "success"}), 200


@bp.route("/uptime-monitors/<string:monitor_id>/check", methods=["POST"])
@jwt_required()
def run_uptime_monitor_check(monitor_id: str):
    try:
        monitor = _get_owned_monitor(monitor_id)
    except PermissionError:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    except LookupError:
        return jsonify({"status": "error", "message": "User not found"}), 404

    check = perform_uptime_check(monitor)
    return jsonify({
        "status": "success",
        "monitor": serialize_monitor(monitor, include_checks=True),
        "check": check.to_dict(),
    }), 200


@bp.route("/uptime-monitors/<string:monitor_id>/checks", methods=["GET"])
@jwt_required()
def list_uptime_monitor_checks(monitor_id: str):
    try:
        monitor = _get_owned_monitor(monitor_id)
    except PermissionError:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    except LookupError:
        return jsonify({"status": "error", "message": "User not found"}), 404

    limit = min(max(request.args.get("limit", 20, type=int), 1), 100)
    return jsonify({
        "status": "success",
        "checks": [check.to_dict() for check in monitor.checks[:limit]],
    }), 200
