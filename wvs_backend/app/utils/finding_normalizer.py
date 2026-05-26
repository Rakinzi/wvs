from __future__ import annotations

import hashlib
from collections import Counter
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
    }
