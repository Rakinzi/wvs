from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from app.utils.finding_model import extract_universal_findings


VERDICT_LABELS = {
    "ready_to_ship": "Ready To Ship",
    "fix_before_shipping": "Fix Before Shipping",
    "blocked": "Blocked",
    "monitor_after_launch": "Monitor After Launch",
}


SCAN_PROFILE_META = {
    "full_scan": {
        "label": "Controlled Security Audit",
        "description": "Security-focused scan using configured passive and active checks.",
        "permission_level": 2,
        "active_testing": True,
    },
    "product_readiness": {
        "label": "Passive Product Readiness",
        "description": "Rendered-page checks for accessibility, mobile UX, performance, SEO, forms, and optional AI visual review.",
        "permission_level": 1,
        "active_testing": False,
    },
    "full_launch_audit": {
        "label": "Full Launch Audit",
        "description": "Combined security and product-readiness scan for approved targets.",
        "permission_level": 2,
        "active_testing": True,
    },
    "security_only": {
        "label": "Controlled Security Audit",
        "description": "Security-focused scan using configured checks.",
        "permission_level": 2,
        "active_testing": True,
    },
}


LIMITATION_TEXT = (
    "LaunchGuard performs automated security, UX, accessibility, SEO and reliability checks "
    "against the approved target and selected pages. A READY TO SHIP verdict means no configured "
    "launch-blocking issues were detected during this scan. It does not guarantee the application "
    "is free of vulnerabilities, accessible in every scenario, or protected against future failures. "
    "High-risk applications handling payments, personal data, or sensitive workflows should undergo "
    "additional manual security review."
)


def _sort_key(finding: Mapping[str, Any]) -> tuple[int, int, str]:
    impact_weight = {
        "blocked": 0,
        "fix_before_ship": 1,
        "monitor_after_ship": 2,
        "recommendation": 3,
    }
    severity_weight = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "recommendation": 4,
        "informational": 5,
    }
    return (
        impact_weight.get(str(finding.get("launch_impact")), 9),
        severity_weight.get(str(finding.get("severity")), 9),
        str(finding.get("title") or ""),
    )


def _verdict_from_counts(blockers: list[dict[str, Any]], fix_before: list[dict[str, Any]], monitor: list[dict[str, Any]]) -> str:
    if blockers:
        return "blocked"
    if fix_before:
        return "fix_before_shipping"
    if monitor:
        return "monitor_after_launch"
    return "ready_to_ship"


def _summary(verdict: str, blockers: list[dict[str, Any]], fix_before: list[dict[str, Any]], monitor: list[dict[str, Any]]) -> str:
    if verdict == "blocked":
        return f"{len(blockers)} confirmed launch blocker{'s' if len(blockers) != 1 else ''} must be fixed before shipping."
    if verdict == "fix_before_shipping":
        return f"{len(fix_before)} important issue{'s' if len(fix_before) != 1 else ''} should be fixed before shipping."
    if verdict == "monitor_after_launch":
        return f"{len(monitor)} lower-risk issue{'s' if len(monitor) != 1 else ''} can ship with monitoring."
    return "No configured launch-blocking issues were detected."


def build_launch_verdict(findings: Mapping[str, Any]) -> dict[str, Any]:
    universal = extract_universal_findings(findings)
    ordered = sorted(universal, key=_sort_key)
    blockers = [item for item in ordered if item.get("launch_impact") == "blocked"]
    fix_before = [item for item in ordered if item.get("launch_impact") == "fix_before_ship"]
    monitor = [item for item in ordered if item.get("launch_impact") == "monitor_after_ship"]
    recommendations = [item for item in ordered if item.get("launch_impact") == "recommendation"]
    verdict = _verdict_from_counts(blockers, fix_before, monitor)
    profile_key = str(findings.get("scan_profile") or "full_scan")
    profile = SCAN_PROFILE_META.get(profile_key, {
        "label": profile_key.replace("_", " ").title(),
        "description": "Configured LaunchGuard scan profile.",
        "permission_level": None,
        "active_testing": None,
    })
    evidence_counts = Counter(str(item.get("evidence_type") or "unknown") for item in universal)
    impact_counts = Counter(str(item.get("launch_impact") or "unknown") for item in universal)

    next_action = {
        "blocked": "Fix the launch blockers, rotate any exposed credentials where needed, then run a verification scan.",
        "fix_before_shipping": "Fix the important issues, then re-scan to confirm the launch risk has dropped.",
        "monitor_after_launch": "You can ship with caution, but establish monitoring and schedule a follow-up scan.",
        "ready_to_ship": "Ship with normal monitoring. Re-scan after major code, dependency, or deployment changes.",
    }[verdict]

    ai_enabled = bool((findings.get("visual_ai") or {}).get("status") not in {None, "disabled", "not_run"})
    limitations = [LIMITATION_TEXT]
    if ai_enabled:
        limitations.append(
            "AI visual review is advisory. Screenshot-based recommendations are not confirmed technical failures."
        )

    return {
        "verdict": verdict,
        "label": VERDICT_LABELS[verdict],
        "summary": _summary(verdict, blockers, fix_before, monitor),
        "next_action": next_action,
        "confidence": "high" if not recommendations else "mixed",
        "scan_profile": {
            "key": profile_key,
            **profile,
        },
        "counts": {
            "total_findings": len(universal),
            "blockers": len(blockers),
            "fix_before_ship": len(fix_before),
            "monitor_after_ship": len(monitor),
            "recommendations": len(recommendations),
            "evidence_types": dict(evidence_counts),
            "launch_impacts": dict(impact_counts),
        },
        "top_blockers": blockers[:5],
        "important_issues": fix_before[:5],
        "monitoring_items": monitor[:5],
        "recommendations": recommendations[:5],
        "universal_findings": ordered,
        "limitations": limitations,
    }
