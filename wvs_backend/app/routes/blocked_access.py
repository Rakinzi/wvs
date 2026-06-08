from __future__ import annotations

from datetime import timedelta
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends

from app import db
from app.auth import require_admin
from app.models import BlockedRequest, User
from app.utils.time_utils import utc_now

router = APIRouter()


def _fmt(b: BlockedRequest) -> dict:
    return {
        "id": b.id,
        "url": b.url,
        "ip_address": b.ip_address,
        "user_agent": b.user_agent,
        "timestamp": b.timestamp.isoformat() if b.timestamp else None,
        "reason": b.reason,
    }


@router.get("/blocked-access/list")
def get_blocked_access(
    admin: Annotated[User, Depends(require_admin)],
    limit: int = 100,
    offset: int = 0,
):
    rows = BlockedRequest.query.order_by(BlockedRequest.timestamp.desc()).limit(limit).offset(offset).all()
    total = BlockedRequest.query.count()
    return {"status": "success", "blocked_requests": [_fmt(b) for b in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/blocked-access/stats")
def get_blocked_access_stats(admin: Annotated[User, Depends(require_admin)]):
    seven_days_ago = utc_now() - timedelta(days=7)
    attempts_by_day = (
        db.session.query(db.func.date(BlockedRequest.timestamp).label("date"), db.func.count(BlockedRequest.id).label("count"))
        .filter(BlockedRequest.timestamp >= seven_days_ago)
        .group_by(db.func.date(BlockedRequest.timestamp))
        .all()
    )
    days_data = []
    for i in range(7):
        day = (utc_now() - timedelta(days=i)).date()
        count = 0
        for attempt_day, attempt_count in attempts_by_day:
            if hasattr(attempt_day, "date"):
                attempt_day = attempt_day.date()
            if attempt_day == day:
                count = attempt_count
                break
        days_data.append({"date": day.isoformat(), "count": count})

    total_blocked = BlockedRequest.query.count()
    today_blocked = BlockedRequest.query.filter(
        BlockedRequest.timestamp >= utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()

    browser_counts = []
    for browser in ["Firefox", "Chrome", "Safari", "Edge", "MSIE", "Opera"]:
        count = BlockedRequest.query.filter(BlockedRequest.user_agent.ilike(f"%{browser}%")).count()
        if count > 0:
            browser_counts.append({"browser": browser, "count": count})

    domain_results = (
        db.session.query(BlockedRequest.url, db.func.count(BlockedRequest.id).label("count"))
        .group_by(BlockedRequest.url)
        .order_by(db.func.count(BlockedRequest.id).desc())
        .limit(10)
        .all()
    )
    top_domains = []
    for url, count in domain_results:
        try:
            domain = urlparse(url).netloc
            if domain:
                top_domains.append({"domain": domain, "count": count})
        except Exception:
            pass

    return {
        "status": "success",
        "stats": {
            "total_blocked": total_blocked,
            "today_blocked": today_blocked,
            "days_data": days_data,
            "browser_counts": browser_counts,
            "top_domains": top_domains,
        },
    }


@router.get("/dashboard/recent-blocked")
def get_recent_blocked(admin: Annotated[User, Depends(require_admin)]):
    rows = BlockedRequest.query.order_by(BlockedRequest.timestamp.desc()).limit(5).all()
    return {"status": "success", "recent_blocked": [_fmt(b) for b in rows]}
