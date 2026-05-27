from __future__ import annotations

from datetime import timedelta
import time

import httpx

from app import db
from app.models import UptimeCheck, UptimeMonitor
from app.settings import settings
from app.utils.scan_helpers import normalize_target_url
from app.utils.time_utils import utc_now


def calculate_uptime_percent(monitor: UptimeMonitor, hours: int = 24) -> float | None:
    cutoff = utc_now() - timedelta(hours=hours)
    checks = [
        check
        for check in monitor.checks
        if check.checked_at and check.checked_at >= cutoff
    ]
    if not checks:
        return None
    up_count = sum(1 for check in checks if check.status == "up")
    return round((up_count / len(checks)) * 100, 1)


def serialize_monitor(monitor: UptimeMonitor, include_checks: bool = False, check_limit: int = 20) -> dict:
    payload = {
        **monitor.to_dict(),
        "uptime_percent_24h": calculate_uptime_percent(monitor, hours=24),
        "recent_checks": [],
    }
    if include_checks:
        payload["recent_checks"] = [
            check.to_dict()
            for check in monitor.checks[:check_limit]
        ]
    return payload


def validate_monitor_target(raw_url: str) -> str:
    return normalize_target_url(raw_url)


def monitor_is_due(monitor: UptimeMonitor, now=None) -> bool:
    if not monitor.is_enabled:
        return False
    current_time = now or utc_now()
    if monitor.last_checked_at is None:
        return True
    return monitor.last_checked_at + timedelta(minutes=monitor.check_interval_minutes) <= current_time


def perform_uptime_check(monitor: UptimeMonitor) -> UptimeCheck:
    checked_at = utc_now()
    start_time = time.perf_counter()

    status = "down"
    status_code = None
    response_time_ms = None
    error_message = None

    try:
        with httpx.Client(
            timeout=settings.uptime_monitor_request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "WVS-UptimeMonitor/1.0"},
        ) as client:
            response = client.get(monitor.target_url)
            response_time_ms = int((time.perf_counter() - start_time) * 1000)
            status_code = response.status_code
            if 200 <= response.status_code < 400:
                status = "up"
            else:
                error_message = f"Unexpected HTTP {response.status_code}"
    except Exception as exc:
        response_time_ms = int((time.perf_counter() - start_time) * 1000)
        error_message = str(exc)

    check = UptimeCheck(
        monitor=monitor,
        status=status,
        status_code=status_code,
        response_time_ms=response_time_ms,
        error_message=error_message,
        checked_at=checked_at,
    )
    db.session.add(check)

    monitor.last_checked_at = checked_at
    monitor.last_response_time_ms = response_time_ms
    if status == "up":
        monitor.status = "up"
        monitor.last_up_at = checked_at
        monitor.consecutive_failures = 0
    else:
        monitor.status = "down"
        monitor.consecutive_failures = (monitor.consecutive_failures or 0) + 1

    db.session.commit()
    return check

