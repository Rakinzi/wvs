from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Any, Mapping


ALLOWED_CONFIDENCE = {"measured", "heuristic", "ai_assisted"}
ALLOWED_SEVERITY = {
    "critical",
    "high",
    "medium",
    "low",
    "recommendation",
    "informational",
}
_TITLE_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "recommendation": "Recommendation",
    "informational": "Informational",
}
_READINESS_AREAS = {
    "accessibility": "UX",
    "responsive_ux": "UX",
    "performance_ux": "UX",
    "form_usability": "UX",
    "broken_links": "UX",
    "seo": "SEO",
    "app_controls": "Security Readiness",
    "route_discovery": "Security Readiness",
    "abuse_controls": "Security Readiness",
    "exposed_services": "Infrastructure",
    "visual_ai": "Advisory",
}
_OWNERS = {
    "accessibility": "Frontend/UI",
    "responsive_ux": "Frontend/UI",
    "performance_ux": "Frontend/Performance",
    "form_usability": "Frontend/UI",
    "broken_links": "Frontend/Content",
    "seo": "Frontend/SEO",
    "app_controls": "Backend/Security",
    "route_discovery": "Backend/Auth",
    "abuse_controls": "Backend/Security",
    "exposed_services": "DevOps/Hosting",
    "visual_ai": "Design/Frontend",
}


def _normalize_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in ALLOWED_SEVERITY else "informational"


def _normalize_confidence(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in ALLOWED_CONFIDENCE else "heuristic"


def _normalize_evidence(evidence: Any) -> dict[str, Any]:
    payload = evidence if isinstance(evidence, Mapping) else {}
    return {
        "rule_id": str(payload.get("rule_id") or ""),
        "description": str(payload.get("description") or ""),
        "element": payload.get("element") if isinstance(payload.get("element"), Mapping) else {},
        "element_summary": str(payload.get("element_summary") or ""),
        "html": str(payload.get("html") or ""),
        "screenshot_path": payload.get("screenshot_path"),
        "metric": payload.get("metric"),
        "value": payload.get("value"),
        "threshold": payload.get("threshold"),
    }


def _stable_finding_id(finding: Mapping[str, Any]) -> str:
    fingerprint = "|".join(
        [
            str(finding.get("scanner") or ""),
            str(finding.get("title") or ""),
            str(finding.get("page_url") or ""),
            str(finding.get("viewport") or ""),
            str(finding.get("selector") or ""),
        ]
    )
    return hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:16]


def readiness_area_for_scanner(scanner: str) -> str:
    return _READINESS_AREAS.get(scanner, "Product Readiness")


def owner_for_finding(scanner: str, title: str = "") -> str:
    lowered = title.lower()
    if "mfa" in lowered or "verification" in lowered:
        return "Backend/Auth"
    if "rate limit" in lowered or "throttl" in lowered:
        return "Backend/Security"
    if "port" in lowered or "service" in lowered:
        return "DevOps/Hosting"
    return _OWNERS.get(scanner, "Engineering")


def fix_effort_for_finding(scanner: str, title: str = "", severity: str = "") -> str:
    lowered = title.lower()
    if scanner in {"app_controls", "route_discovery", "abuse_controls"}:
        if any(term in lowered for term in ("protected", "admin", "dashboard", "webhook", "upload", "rate limit", "mfa", "verification")):
            return "Needs backend review"
    if scanner == "exposed_services":
        return "Needs deployment/config review"
    if scanner == "performance_ux":
        return "1-2 hours"
    if scanner == "seo":
        if any(term in lowered for term in ("structured data", "open graph", "twitter")):
            return "30-60 min"
        return "5-30 min"
    if scanner in {"accessibility", "responsive_ux", "form_usability", "broken_links"}:
        if str(severity).lower() in {"critical", "high"}:
            return "30-60 min"
        return "5-30 min"
    return "Review required"


def blocker_reason_for_finding(scanner: str, title: str = "") -> str:
    lowered = title.lower()
    if "label" in lowered or "accessible name" in lowered:
        return "Blocks launch because screen-reader and voice-command users may not be able to identify or complete key controls."
    if "tap target" in lowered:
        return "Blocks mobile readiness because touch users may miss the control or hit a nearby action."
    if "submit" in lowered:
        return "Blocks launch because users may not be able to complete the visible form workflow."
    if "protected" in lowered or "admin" in lowered or "dashboard" in lowered:
        return "Blocks launch because private account or admin surfaces may be reachable without server-side authorization."
    if "webhook" in lowered or "callback" in lowered:
        return "Needs review because public webhook routes are normal only when signature verification is enforced."
    if "upload" in lowered:
        return "Needs review because public upload routes can be abused unless authentication, validation, and storage controls are enforced."
    if scanner == "exposed_services":
        return "Needs review because unexpected public services increase the target attack surface."
    if scanner == "seo":
        return "Affects launch discoverability and share previews, but usually does not block core user workflows."
    if scanner == "performance_ux":
        return "Affects mobile data use and perceived speed, especially on slower connections."
    return "Review this before launch because it can affect user trust, completion, or operational readiness."


def normalize_ux_finding(
    finding: Mapping[str, Any],
    *,
    default_scanner: str = "ux",
    default_category: str | None = None,
) -> dict[str, Any]:
    scanner = str(finding.get("scanner") or default_scanner).strip() or default_scanner
    category = str(
        finding.get("category")
        or default_category
        or scanner.replace("_", " ").title()
    ).strip()
    normalized = {
        "id": str(finding.get("id") or ""),
        "scanner": scanner,
        "category": category,
        "title": str(finding.get("title") or "Untitled finding"),
        "severity": _normalize_severity(finding.get("severity")),
        "confidence": _normalize_confidence(finding.get("confidence") or "measured"),
        "page_url": str(finding.get("page_url") or ""),
        "viewport": str(finding.get("viewport") or ""),
        "selector": finding.get("selector"),
        "evidence": _normalize_evidence(finding.get("evidence")),
        "user_impact": str(finding.get("user_impact") or ""),
        "technical_remediation": str(finding.get("technical_remediation") or ""),
        "builder_prompt": str(finding.get("builder_prompt") or ""),
        "references": [str(item) for item in (finding.get("references") or [])],
        "status": str(finding.get("status") or "open"),
    }
    normalized["readiness_area"] = str(finding.get("readiness_area") or readiness_area_for_scanner(scanner))
    normalized["owner"] = str(finding.get("owner") or owner_for_finding(scanner, normalized["title"]))
    normalized["fix_effort"] = str(finding.get("fix_effort") or fix_effort_for_finding(scanner, normalized["title"], normalized["severity"]))
    normalized["blocker_reason"] = str(finding.get("blocker_reason") or blocker_reason_for_finding(scanner, normalized["title"]))
    normalized["technical_details"] = {
        "selector": normalized["selector"],
        "rule_id": normalized["evidence"].get("rule_id"),
        "element": normalized["evidence"].get("element_summary") or normalized["evidence"].get("html"),
    }
    if not normalized["id"]:
        normalized["id"] = _stable_finding_id(normalized)
    return normalized


def normalize_ux_findings(
    findings: list[Mapping[str, Any]],
    *,
    default_scanner: str = "ux",
    default_category: str | None = None,
) -> list[dict[str, Any]]:
    return [
        normalize_ux_finding(
            finding,
            default_scanner=default_scanner,
            default_category=default_category,
        )
        for finding in findings
    ]


def count_findings_by_scanner(findings: list[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter(str(finding.get("scanner") or "ux") for finding in findings)
    return dict(counts)


def group_report_findings(findings: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for finding in findings:
        scanner = str(finding.get("scanner") or "ux")
        title = str(finding.get("title") or finding.get("name") or "Untitled finding")
        severity = _normalize_severity(finding.get("severity"))
        grouped[(scanner, title, severity)].append(finding)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "recommendation": 4, "informational": 5}
    groups: list[dict[str, Any]] = []
    for (scanner, title, severity), items in grouped.items():
        first = items[0]
        example = normalize_ux_finding(first, default_scanner=scanner, default_category=str(first.get("category") or ""))
        selectors = [str(item.get("selector")) for item in items if item.get("selector")]
        pages = [str(item.get("page_url") or item.get("url") or "") for item in items if item.get("page_url") or item.get("url")]
        group_id = hashlib.sha1("|".join([scanner, title, severity]).encode("utf-8")).hexdigest()[:16]
        groups.append({
            "id": group_id,
            "title": title,
            "severity": severity,
            "confidence": example.get("confidence"),
            "scanner": scanner,
            "category": example.get("category"),
            "readiness_area": example.get("readiness_area"),
            "owner": example.get("owner"),
            "fix_effort": example.get("fix_effort"),
            "blocker_reason": example.get("blocker_reason"),
            "count": len(items),
            "example_selector": selectors[0] if selectors else None,
            "example_page_url": pages[0] if pages else "",
            "instances": [
                {
                    "id": str(item.get("id") or ""),
                    "page_url": str(item.get("page_url") or item.get("url") or ""),
                    "viewport": str(item.get("viewport") or ""),
                    "selector": item.get("selector"),
                    "element": ((item.get("evidence") or {}).get("element_summary") if isinstance(item.get("evidence"), Mapping) else ""),
                }
                for item in items[:10]
            ],
        })
    return sorted(groups, key=lambda item: (severity_order.get(str(item.get("severity")), 9), -int(item.get("count") or 0), str(item.get("title") or "")))


def to_report_finding(finding: Mapping[str, Any]) -> dict[str, Any]:
    evidence = _normalize_evidence(finding.get("evidence"))
    evidence_parts = [part for part in [evidence["description"]] if part]
    if evidence["metric"] and evidence["value"] is not None:
        if evidence["threshold"] is not None:
            evidence_parts.append(
                f"{evidence['metric']}: {evidence['value']} (threshold: {evidence['threshold']})"
            )
        else:
            evidence_parts.append(f"{evidence['metric']}: {evidence['value']}")

    return {
        "name": str(finding.get("title") or "Untitled finding"),
        "severity": _TITLE_SEVERITY.get(
            _normalize_severity(finding.get("severity")),
            "Informational",
        ),
        "evidence": " | ".join(evidence_parts) or "No evidence captured.",
        "confidence": _normalize_confidence(finding.get("confidence") or "measured"),
        "page_url": str(finding.get("page_url") or ""),
        "viewport": str(finding.get("viewport") or ""),
        "selector": finding.get("selector"),
        "builder_prompt": str(finding.get("builder_prompt") or ""),
        "category": str(finding.get("category") or ""),
        "scanner": str(finding.get("scanner") or "ux"),
        "status": str(finding.get("status") or "open"),
        "screenshot_path": evidence.get("screenshot_path"),
        "readiness_area": str(finding.get("readiness_area") or readiness_area_for_scanner(str(finding.get("scanner") or "ux"))),
        "owner": str(finding.get("owner") or owner_for_finding(str(finding.get("scanner") or "ux"), str(finding.get("title") or ""))),
        "fix_effort": str(finding.get("fix_effort") or fix_effort_for_finding(str(finding.get("scanner") or "ux"), str(finding.get("title") or ""), str(finding.get("severity") or ""))),
        "blocker_reason": str(finding.get("blocker_reason") or blocker_reason_for_finding(str(finding.get("scanner") or "ux"), str(finding.get("title") or ""))),
    }
