from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import ValidationError

from app import db
from app.auth import current_user, require_admin
from app.models import BlockedRequest, MaliciousSite, User
from app.schemas import AddMaliciousPayload, BlockedLogPayload
from app.utils.db_manager import DBManager
from app.utils.scan_helpers import normalize_target_url
from app.utils.time_utils import utc_now

router = APIRouter()


@router.get("/api/malicious/check")
def check_malicious(url: str = Query(...)):
    try:
        url = normalize_target_url(url)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    is_blocked, reason = DBManager.check_malicious_url(url)
    if is_blocked:
        return {"url": url, "blocked": True, "reason": reason or "Domain in database", "source": "database"}

    from app.scanners import SecurityScanner
    scanner = SecurityScanner()
    malicious_result = scanner.malicious_detector.analyze_url(url)

    if malicious_result["is_malicious"]:
        parts = []
        if malicious_result["phishing_match"]: parts.append("Phishing site")
        if malicious_result["dnsbl"].get("blacklisted"): parts.append("Listed in DNS blacklists")
        if malicious_result["score"] >= 7: parts.append("Suspicious URL characteristics")
        reason_str = " | ".join(parts) or "Malicious site"
        DBManager.add_malicious_url(url, reason_str, "scanner")
        return {"url": url, "blocked": True, "reason": reason_str, "details": malicious_result, "source": "rule_engine"}

    try:
        prediction_int, prediction_label, prediction_source = scanner.check_ai(url)
        if prediction_label in ["phishing", "malware", "defacement"]:
            reason_str = f"AI classified as {prediction_label}"
            DBManager.add_malicious_url(url, reason_str, "ai")
            return {"url": url, "blocked": True, "reason": reason_str, "source": prediction_source,
                    "ai": {"backend": prediction_source, "label": prediction_label, "prediction": prediction_int}}
    except Exception:
        pass

    return {"url": url, "blocked": False, "source": "none"}


@router.get("/api/malicious/list")
def list_malicious(
    admin: Annotated[User, Depends(require_admin)],
    since: int = Query(default=0),
    limit: int = Query(default=1000, le=1000),
):
    if since > 0:
        since_date = datetime.fromtimestamp(since)
        sites = MaliciousSite.query.filter(MaliciousSite.date_added > since_date).limit(limit).all()
    else:
        sites = MaliciousSite.query.limit(limit).all()
    return {"count": len(sites), "domains": [s.domain for s in sites], "sites": [s.to_dict() for s in sites]}


@router.post("/api/malicious/add", status_code=201)
async def add_malicious(request: Request, admin: Annotated[User, Depends(require_admin)]):
    try:
        data = await request.json()
        payload = AddMaliciousPayload.model_validate(data)
        url = normalize_target_url(payload.url)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))

    success = DBManager.add_malicious_url(url, payload.reason, "manual")
    if success:
        return {"status": "success", "message": "URL added to malicious database"}
    return {"status": "warning", "message": "URL already exists in database"}


@router.post("/api/blocked/log", status_code=201)
async def log_blocked(request: Request):
    try:
        data = await request.json()
        payload = BlockedLogPayload.model_validate(data)
        url = normalize_target_url(payload.url)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))

    log = BlockedRequest(url=url, ip_address=payload.ip_address, user_agent=payload.user_agent, reason=payload.reason)
    db.session.add(log)
    db.session.commit()
    return {"status": "success"}


@router.get("/api/blocked/stats")
def blocked_stats(
    admin: Annotated[User, Depends(require_admin)],
    period: str = Query(default="day"),
):
    if period == "hour":
        since = utc_now().replace(minute=0, second=0, microsecond=0)
        data = db.session.query(db.func.count(BlockedRequest.id)).filter(BlockedRequest.timestamp >= since).scalar()
    elif period == "day":
        since = utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
        data = db.session.query(db.func.count(BlockedRequest.id)).filter(BlockedRequest.timestamp >= since).scalar()
    elif period == "week":
        rows = (
            db.session.query(db.func.date(BlockedRequest.timestamp).label("date"), db.func.count(BlockedRequest.id).label("count"))
            .group_by("date")
            .all()
        )
        data = {str(r[0]): r[1] for r in rows}
    else:
        raise HTTPException(400, "Invalid period")

    return {"status": "success", "period": period, "data": data}
