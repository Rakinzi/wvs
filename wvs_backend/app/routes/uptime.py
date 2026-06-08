from __future__ import annotations

from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import ValidationError

from app import db
from app.auth import current_user
from app.models import UptimeMonitor, User, VerifiedTarget
from app.schemas import UptimeMonitorCreatePayload, UptimeMonitorUpdatePayload
from app.services.uptime import perform_uptime_check, serialize_monitor, validate_monitor_target

router = APIRouter()


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _owned_monitor(monitor_id: str, user: User) -> UptimeMonitor:
    monitor = UptimeMonitor.query.filter_by(public_id=monitor_id).first_or_404()
    if monitor.user_id != user.id and not user.is_admin:
        raise HTTPException(403, "Unauthorized")
    return monitor


@router.get("/uptime-monitors")
def list_uptime_monitors(user: Annotated[User, Depends(current_user)]):
    monitors = UptimeMonitor.query.filter_by(user_id=user.id).order_by(UptimeMonitor.created_at.desc()).all()
    return {"status": "success", "monitors": [serialize_monitor(m) for m in monitors]}


@router.post("/uptime-monitors", status_code=201)
async def create_uptime_monitor(request: Request, user: Annotated[User, Depends(current_user)]):
    try:
        data = await request.json()
        payload = UptimeMonitorCreatePayload.model_validate(data)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))

    verified_target = VerifiedTarget.query.filter_by(
        public_id=payload.verified_target_id, user_id=user.id, verification_status="verified"
    ).first()
    if not verified_target:
        raise HTTPException(403, "Choose a verified target before adding an uptime monitor.")
    if verified_target.normalized_domain.lower() != _hostname(payload.target_url):
        raise HTTPException(400, "The monitor URL must match the selected verified target.")

    try:
        target_url = validate_monitor_target(payload.target_url)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    monitor = UptimeMonitor(name=payload.name, target_url=target_url, check_interval_minutes=payload.check_interval_minutes, user_id=user.id)
    db.session.add(monitor)
    db.session.commit()
    return {"status": "success", "monitor": serialize_monitor(monitor)}


@router.get("/uptime-monitors/{monitor_id}")
def get_uptime_monitor(monitor_id: str, user: Annotated[User, Depends(current_user)]):
    monitor = _owned_monitor(monitor_id, user)
    return {"status": "success", "monitor": serialize_monitor(monitor, include_checks=True)}


@router.patch("/uptime-monitors/{monitor_id}")
async def update_uptime_monitor(monitor_id: str, request: Request, user: Annotated[User, Depends(current_user)]):
    monitor = _owned_monitor(monitor_id, user)
    try:
        data = await request.json()
        payload = UptimeMonitorUpdatePayload.model_validate(data)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))

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
    return {"status": "success", "monitor": serialize_monitor(monitor)}


@router.delete("/uptime-monitors/{monitor_id}")
def delete_uptime_monitor(monitor_id: str, user: Annotated[User, Depends(current_user)]):
    monitor = _owned_monitor(monitor_id, user)
    db.session.delete(monitor)
    db.session.commit()
    return {"status": "success"}


@router.post("/uptime-monitors/{monitor_id}/check")
def run_uptime_monitor_check(monitor_id: str, user: Annotated[User, Depends(current_user)]):
    monitor = _owned_monitor(monitor_id, user)
    check = perform_uptime_check(monitor)
    return {"status": "success", "monitor": serialize_monitor(monitor, include_checks=True), "check": check.to_dict()}


@router.get("/uptime-monitors/{monitor_id}/checks")
def list_uptime_monitor_checks(monitor_id: str, user: Annotated[User, Depends(current_user)], limit: int = Query(default=20, ge=1, le=100)):
    monitor = _owned_monitor(monitor_id, user)
    return {"status": "success", "checks": [c.to_dict() for c in monitor.checks[:limit]]}
