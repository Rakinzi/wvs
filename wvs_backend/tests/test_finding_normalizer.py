from __future__ import annotations

from app.utils.finding_normalizer import (
    ALLOWED_CONFIDENCE,
    ALLOWED_SEVERITY,
    count_findings_by_scanner,
    group_report_findings,
    normalize_ux_finding,
    to_report_finding,
)


def test_normalize_ux_finding_applies_defaults_and_normalizes_values():
    finding = normalize_ux_finding(
        {
            "scanner": "accessibility",
            "title": "Form input has no accessible label",
            "severity": "HIGH",
            "confidence": "MEASURED",
            "page_url": "https://example.com/signup",
            "viewport": "mobile",
            "selector": "#email",
            "evidence": {"rule_id": "label"},
        }
    )

    assert finding["scanner"] == "accessibility"
    assert finding["category"] == "Accessibility"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "measured"
    assert finding["status"] == "open"
    assert finding["id"]
    assert finding["evidence"]["rule_id"] == "label"
    assert finding["evidence"]["description"] == ""
    assert finding["readiness_area"] == "UX"
    assert finding["owner"] == "Frontend/UI"
    assert finding["fix_effort"] == "30-60 min"
    assert "screen-reader" in finding["blocker_reason"]


def test_normalize_ux_finding_rejects_unknown_labels_with_safe_fallbacks():
    finding = normalize_ux_finding(
        {
            "title": "Unknown severity and confidence values",
            "severity": "urgent",
            "confidence": "llm",
        },
        default_scanner="visual_ai",
        default_category="Visual UX",
    )

    assert finding["scanner"] == "visual_ai"
    assert finding["category"] == "Visual UX"
    assert finding["severity"] == "informational"
    assert finding["confidence"] == "heuristic"


def test_to_report_finding_supplies_pdf_safe_fields():
    normalized = normalize_ux_finding(
        {
            "scanner": "responsive_ux",
            "title": "Horizontal overflow on mobile",
            "severity": "medium",
            "page_url": "https://example.com",
            "viewport": "mobile",
            "evidence": {
                "description": "Document width exceeds viewport width.",
                "value": 430,
                "threshold": 390,
            },
        }
    )

    report_finding = to_report_finding(normalized)

    assert report_finding["name"] == "Horizontal overflow on mobile"
    assert report_finding["severity"] == "Medium"
    assert "Document width exceeds viewport width." in report_finding["evidence"]
    assert report_finding["confidence"] == "measured"


def test_normalize_ux_finding_preserves_element_context():
    finding = normalize_ux_finding(
        {
            "scanner": "accessibility",
            "title": "Form elements must have labels",
            "selector": "#header-search",
            "evidence": {
                "rule_id": "label",
                "description": '<input id="header-search" type="search"> has no associated label.',
                "element_summary": '<input id="header-search" type="search">',
                "element": {
                    "tag": "input",
                    "attributes": {"id": "header-search", "type": "search"},
                },
                "html": '<input id="header-search" type="search">',
            },
        }
    )

    assert finding["evidence"]["element_summary"] == '<input id="header-search" type="search">'
    assert finding["evidence"]["element"]["tag"] == "input"
    assert "header-search" in finding["evidence"]["html"]
    assert finding["technical_details"]["selector"] == "#header-search"


def test_count_findings_by_scanner_aggregates_normalized_findings():
    findings = [
        normalize_ux_finding({"scanner": "accessibility", "title": "A"}),
        normalize_ux_finding({"scanner": "accessibility", "title": "B"}),
        normalize_ux_finding({"scanner": "responsive_ux", "title": "C"}),
    ]

    counts = count_findings_by_scanner(findings)

    assert counts == {"accessibility": 2, "responsive_ux": 1}
    assert "measured" in ALLOWED_CONFIDENCE
    assert "high" in ALLOWED_SEVERITY


def test_group_report_findings_collapses_repeated_issue_types():
    findings = [
        normalize_ux_finding({
            "scanner": "accessibility",
            "title": "Interactive controls must have accessible names",
            "severity": "high",
            "page_url": "https://example.com",
            "selector": "button:nth-of-type(1)",
        }),
        normalize_ux_finding({
            "scanner": "accessibility",
            "title": "Interactive controls must have accessible names",
            "severity": "high",
            "page_url": "https://example.com/shop",
            "selector": "button:nth-of-type(2)",
        }),
        normalize_ux_finding({
            "scanner": "seo",
            "title": "Meta description is missing",
            "severity": "medium",
        }),
    ]

    groups = group_report_findings(findings)

    assert groups[0]["title"] == "Interactive controls must have accessible names"
    assert groups[0]["count"] == 2
    assert groups[0]["owner"] == "Frontend/UI"
    assert groups[0]["example_selector"] == "button:nth-of-type(1)"
    assert groups[1]["readiness_area"] == "SEO"
