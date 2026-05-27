from __future__ import annotations

from app import celery
from app.models import UptimeMonitor
from app.services.uptime import monitor_is_due, perform_uptime_check
from app.utils.time_utils import utc_now


@celery.task(name="app.tasks.run_due_uptime_checks")
def run_due_uptime_checks() -> dict:
    from app import db

    now = utc_now()
    monitors = UptimeMonitor.query.filter_by(is_enabled=True).all()
    checked = 0

    for monitor in monitors:
        if not monitor_is_due(monitor, now=now):
            continue
        perform_uptime_check(monitor)
        checked += 1
        db.session.expire_all()

    return {"checked": checked, "total": len(monitors)}

