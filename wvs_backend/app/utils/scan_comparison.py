from __future__ import annotations

import hashlib
from typing import Any

from app.utils.scan_helpers import build_scan_summary
from app.utils.launch_verdict import build_launch_verdict


SCANNER_KEYS = [
    "sqli",
    "ssl",
    "headers",
    "wordpress",
    "zap",
    "malicious",
    "xss",
    "tech",
    "exposure",
    "dns",
    "redirect",
    "takeover",
    "accessibility",
    "responsive_ux",
    "performance_ux",
    "form_usability",
    "seo",
    "broken_links",
    "app_controls",
    "exposed_services",
    "visual_ai",
]


def _normalize_issue(scanner: str, issue: dict[str, Any]) -> dict[str, Any]:
    title = str(
        issue.get("title")
        or issue.get("name")
        or issue.get("type")
        or f"{scanner} finding"
    )
    severity = str(issue.get("severity") or issue.get("risk") or "informational")
    page_url = str(issue.get("page_url") or issue.get("url") or "")
    selector = str(issue.get("selector") or issue.get("parameter") or "")
    viewport = str(issue.get("viewport") or "")
    fingerprint_source = "|".join([scanner, title, severity, page_url, viewport, selector])
    fingerprint = hashlib.sha1(fingerprint_source.encode("utf-8")).hexdigest()[:16]
    return {
        "id": str(issue.get("id") or fingerprint),
        "scanner": scanner,
        "title": title,
        "severity": severity,
        "page_url": page_url,
        "viewport": viewport,
        "selector": selector or None,
        "user_impact": issue.get("user_impact"),
        "technical_remediation": issue.get("technical_remediation"),
        "builder_prompt": issue.get("builder_prompt"),
        "evidence": issue.get("evidence") if isinstance(issue.get("evidence"), dict) else {"description": issue.get("evidence") or ""},
    }


def _extract_findings(findings: dict[str, Any]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for scanner in SCANNER_KEYS:
        payload = findings.get(scanner) or {}
        if scanner == "sqli" and isinstance(payload, list):
            issues = payload
        elif scanner == "ssl" and isinstance(payload, dict):
            issues = [] if payload.get("valid", True) else [
                {
                    "title": payload.get("error") or "SSL/TLS certificate issue",
                    "severity": "high",
                    "evidence": payload.get("issuer") or "Certificate validation failed",
                }
            ]
        elif scanner == "malicious" and isinstance(payload, dict):
            issues = [] if not payload.get("is_malicious") else [
                {
                    "title": "Target flagged as malicious",
                    "severity": "high",
                    "evidence": payload.get("reason") or "Malicious reputation score exceeded threshold",
                }
            ]
        else:
            issues = payload.get("issues", []) if isinstance(payload, dict) else []

        for issue in issues or []:
            if isinstance(issue, dict):
                collected.append(_normalize_issue(scanner, issue))
    return collected


def build_scan_comparison(current_findings: dict[str, Any], previous_findings: dict[str, Any]) -> dict[str, Any]:
    current_summary = build_scan_summary(current_findings)
    previous_summary = build_scan_summary(previous_findings)
    current_verdict = (current_findings.get("launch_verdict") or build_launch_verdict(current_findings)).get("verdict")
    previous_verdict = (previous_findings.get("launch_verdict") or build_launch_verdict(previous_findings)).get("verdict")

    current_items = {item["id"]: item for item in _extract_findings(current_findings)}
    previous_items = {item["id"]: item for item in _extract_findings(previous_findings)}

    current_ids = set(current_items)
    previous_ids = set(previous_items)

    fixed_ids = sorted(previous_ids - current_ids)
    new_ids = sorted(current_ids - previous_ids)
    unresolved_ids = sorted(current_ids & previous_ids)

    return {
        "fixed_count": len(fixed_ids),
        "new_count": len(new_ids),
        "unresolved_count": len(unresolved_ids),
        "fixed": [previous_items[item_id] for item_id in fixed_ids[:10]],
        "new": [current_items[item_id] for item_id in new_ids[:10]],
        "unresolved": [current_items[item_id] for item_id in unresolved_ids[:10]],
        "summary_delta": {
            "issue_count": current_summary.get("total_issues", 0) - previous_summary.get("total_issues", 0),
            "security_score": _delta(previous_summary.get("security_score"), current_summary.get("security_score")),
            "accessibility_score": _delta(previous_summary.get("accessibility_score"), current_summary.get("accessibility_score")),
            "responsive_score": _delta(previous_summary.get("responsive_score"), current_summary.get("responsive_score")),
            "performance_score": _delta(previous_summary.get("performance_score"), current_summary.get("performance_score")),
            "usability_score": _delta(previous_summary.get("usability_score"), current_summary.get("usability_score")),
            "launch_readiness_score": _delta(previous_summary.get("launch_readiness_score"), current_summary.get("launch_readiness_score")),
        },
        "verdict_delta": {
            "previous": previous_verdict,
            "current": current_verdict,
            "changed": previous_verdict != current_verdict,
        },
    }


def _delta(previous: Any, current: Any) -> int | None:
    if previous is None or current is None:
        return None
    try:
        return int(current) - int(previous)
    except (TypeError, ValueError):
        return None
