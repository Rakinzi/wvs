from __future__ import annotations

import traceback
from collections import Counter
from datetime import timedelta
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from sqlalchemy import func

from app import db
from app.auth import current_user
from app.models import BlockedRequest, MaliciousSite, ScanResult, UptimeMonitor, User
from app.services.uptime import calculate_uptime_percent
from app.utils.scan_helpers import build_scan_summary
from app.utils.time_utils import utc_now

router = APIRouter()

MAX_STATS_SCAN_RESULTS = 500
MAX_SECURITY_FEED_ROWS = 500


@router.get("/api/dashboard/stats")
def get_dashboard_stats(user: Annotated[User, Depends(current_user)]):
    try:
        total_scans = ScanResult.query.filter_by(user_id=user.id).count()
        monitors = UptimeMonitor.query.filter_by(user_id=user.id).order_by(UptimeMonitor.created_at.desc()).all()
        can_view_security_feed = user.is_admin
        blocked_requests, malicious_sites = [], []
        if can_view_security_feed:
            blocked_requests = BlockedRequest.query.order_by(BlockedRequest.timestamp.desc()).limit(MAX_SECURITY_FEED_ROWS).all()
            malicious_sites = MaliciousSite.query.order_by(MaliciousSite.date_added.desc()).limit(MAX_SECURITY_FEED_ROWS).all()

        today_start = utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
        seven_days_ago = utc_now() - timedelta(days=7)

        scan_meta_rows = (
            ScanResult.query.with_entities(ScanResult.id, ScanResult.public_id, ScanResult.url, ScanResult.timestamp)
            .filter(ScanResult.user_id == user.id)
            .order_by(ScanResult.timestamp.desc())
            .limit(MAX_STATS_SCAN_RESULTS)
            .all()
        )
        scan_ids = [row.id for row in scan_meta_rows]
        findings_by_id = {}
        if scan_ids:
            findings_by_id = {
                row.id: row.findings
                for row in ScanResult.query.with_entities(ScanResult.id, ScanResult.findings)
                .filter(ScanResult.id.in_(scan_ids))
                .all()
            }

        today_scans = ScanResult.query.filter(ScanResult.user_id == user.id, ScanResult.timestamp >= today_start).count()
        scan_count_rows = (
            ScanResult.query.with_entities(func.date(ScanResult.timestamp).label("day"), func.count(ScanResult.id).label("count"))
            .filter(ScanResult.user_id == user.id, ScanResult.timestamp >= seven_days_ago)
            .group_by(func.date(ScanResult.timestamp))
            .all()
        )
        scans_by_day_map = {str(row.day): int(row.count) for row in scan_count_rows}

        vuln = {k: 0 for k in ["sql", "ssl", "malicious", "headers", "wordpress", "zap", "xss", "exposure", "dependencies", "malware_artifacts", "total"]}
        today_vulnerabilities = 0
        total_dependency_advisories = 0
        recent_scans = []
        vulnerabilities_by_day_map: dict[str, int] = {}

        for scan in scan_meta_rows:
            findings = findings_by_id.get(scan.id) or {}
            summary = findings.get("summary") or build_scan_summary(findings)
            scan_day = scan.timestamp.strftime("%Y-%m-%d")
            if scan.timestamp >= seven_days_ago and summary["vulnerable"]:
                vulnerabilities_by_day_map[scan_day] = vulnerabilities_by_day_map.get(scan_day, 0) + 1
            if summary["sqli_count"] > 0: vuln["sql"] += 1
            if summary["ssl_issue"]: vuln["ssl"] += 1
            if summary["malicious"]: vuln["malicious"] += 1
            if summary["header_issue_count"] > 0: vuln["headers"] += 1
            if summary.get("wordpress_issue_count", 0) > 0: vuln["wordpress"] += 1
            if summary.get("zap_issue_count", 0) > 0: vuln["zap"] += 1
            if summary.get("xss_count", 0) > 0: vuln["xss"] += 1
            if summary.get("exposure_count", 0) > 0: vuln["exposure"] += 1
            if summary.get("malware_artifact_count", 0) > 0: vuln["malware_artifacts"] += 1
            if summary.get("advisory_count", 0) > 0:
                vuln["dependencies"] += 1
                total_dependency_advisories += summary.get("advisory_count", 0)
            if summary["vulnerable"]:
                vuln["total"] += 1
                if scan.timestamp >= today_start:
                    today_vulnerabilities += 1
            if len(recent_scans) < 5:
                recent_scans.append({"id": scan.public_id, "url": scan.url, "timestamp": scan.timestamp.isoformat(), "hasVulnerabilities": summary["vulnerable"]})

        date_list = [(utc_now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        scans_by_day = [{"date": d, "scans": scans_by_day_map.get(d, 0), "vulnerabilities": vulnerabilities_by_day_map.get(d, 0)} for d in date_list]

        blocked_attempts_by_day_map: dict[str, int] = {}
        today_blocked_attempts = 0
        blocked_domain_counter: Counter[str] = Counter()
        for b in blocked_requests:
            day = b.timestamp.strftime("%Y-%m-%d")
            if b.timestamp >= seven_days_ago:
                blocked_attempts_by_day_map[day] = blocked_attempts_by_day_map.get(day, 0) + 1
            if b.timestamp >= today_start:
                today_blocked_attempts += 1
            domain = urlparse(b.url).netloc
            if domain:
                blocked_domain_counter[domain] += 1

        blocked_attempts_by_day = [{"date": d, "count": blocked_attempts_by_day_map.get(d, 0)} for d in date_list]
        monitors_up = sum(1 for m in monitors if m.status == "up")
        monitors_down = sum(1 for m in monitors if m.status == "down")
        uptime_values = [v for v in (calculate_uptime_percent(m, hours=24) for m in monitors) if v is not None]
        avg_uptime = round(sum(uptime_values) / len(uptime_values), 1) if uptime_values else None
        recent_monitors = [
            {"id": m.public_id, "name": m.name, "target_url": m.target_url, "status": m.status,
             "last_checked_at": m.last_checked_at.isoformat() if m.last_checked_at else None,
             "last_response_time_ms": m.last_response_time_ms, "uptime_percent_24h": calculate_uptime_percent(m, hours=24)}
            for m in monitors[:5]
        ]

        return {
            "status": "success",
            "stats": {
                "totalScans": total_scans,
                "vulnerableScans": vuln["total"],
                "blockedSites": len(malicious_sites),
                "uptimeMonitors": len(monitors),
                "uptimeUp": monitors_up,
                "uptimeDown": monitors_down,
                "averageUptimePercent": avg_uptime,
                "dependencyAdvisories": total_dependency_advisories,
                "today": {"scans": today_scans, "vulnerabilities": today_vulnerabilities, "blockedAttempts": today_blocked_attempts},
                "canViewSecurityFeed": can_view_security_feed,
                "recentScans": recent_scans,
                "vulnerabilityTypes": [
                    {"name": "SQL Injection", "value": vuln["sql"]},
                    {"name": "SSL Issues", "value": vuln["ssl"]},
                    {"name": "Malicious Content", "value": vuln["malicious"]},
                    {"name": "Header Issues", "value": vuln["headers"]},
                    {"name": "WordPress Issues", "value": vuln["wordpress"]},
                    {"name": "ZAP Alerts", "value": vuln["zap"]},
                    {"name": "XSS", "value": vuln["xss"]},
                    {"name": "Dependency CVEs", "value": vuln["dependencies"]},
                    {"name": "File Exposure", "value": vuln["exposure"]},
                    {"name": "Malware Artifacts", "value": vuln["malware_artifacts"]},
                ],
                "scansByDay": scans_by_day,
                "blockedAttemptsByDay": blocked_attempts_by_day,
                "topMaliciousDomains": [{"domain": d, "count": c} for d, c in blocked_domain_counter.most_common(5)],
                "recentMonitors": recent_monitors,
                "recentBlockedAttempts": [_fmt_blocked(b) for b in blocked_requests[:5]],
            },
        }
    except Exception as e:
        traceback.print_exc()
        raise


def _fmt_blocked(b: BlockedRequest) -> dict:
    return {"id": b.id, "url": b.url, "ip_address": b.ip_address, "timestamp": b.timestamp.isoformat() if b.timestamp else None, "reason": b.reason}
