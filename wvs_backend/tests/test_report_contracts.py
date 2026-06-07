from __future__ import annotations

from datetime import datetime, timezone

from app import db
from app.models import ScanResult
from app.utils.reports import generate_report
from app.utils.scan_helpers import build_scan_sections, build_scan_summary


def test_build_scan_summary_preserves_legacy_issue_count_logic():
    findings = {
        "sqli": [{"name": "SQL injection in login", "severity": "High"}],
        "ssl": {"valid": False, "self_signed": False},
        "malicious": {"is_malicious": True},
        "headers": {"issues": [{"name": "Missing CSP", "severity": "Medium"}]},
        "wordpress": {"issues": [{"name": "XML-RPC enabled", "severity": "Medium"}]},
        "zap": {"issues": [{"name": "Reflected XSS", "risk": "High"}]},
        "xss": {"issues": [{"name": "Reflected XSS", "type": "Reflected XSS", "severity": "High"}]},
        "tech": {
            "issues": [{"name": "Server version exposed", "severity": "Low"}],
            "packages": [{"name": "react", "version": "19.0.0"}],
            "advisories": [{"id": "CVE-2026-0001"}],
        },
        "exposure": {"issues": [{"name": ".env exposed", "severity": "Critical"}]},
        "dns": {"issues": [{"name": "Missing DMARC", "severity": "Medium"}]},
        "redirect": {"issues": [{"name": "Open redirect", "severity": "High"}]},
        "takeover": {"issues": [{"name": "Dangling CNAME", "severity": "High"}]},
    }

    summary = build_scan_summary(findings)

    assert summary["vulnerable"] is True
    assert summary["sqli_count"] == 1
    assert summary["ssl_issue"] is True
    assert summary["malicious"] is True
    assert summary["xss_count"] == 1
    assert summary["package_count"] == 1
    assert summary["advisory_count"] == 1
    assert summary["exposure_count"] == 1
    assert summary["redirect_count"] == 1
    assert summary["takeover_count"] == 1
    assert summary["total_issues"] == 13
    assert summary["score_breakdown"]["overall"]["score"] == summary["security_score"]
    assert "UX Score" == summary["score_breakdown"]["ux"]["label"]


def test_build_scan_sections_preserves_expected_section_shape():
    findings = {
        "headers": {
            "status": "issues_found",
            "issues": [{"name": "Missing HSTS", "severity": "Medium", "evidence": "Header absent"}],
            "recommendations": ["Add Strict-Transport-Security."],
        },
        "xss": {
            "status": "issues_found",
            "issues": [{"name": "Reflected XSS", "severity": "High", "payload": "<svg/onload=1>"}],
            "recommendations": ["Encode output."],
        },
    }

    sections = build_scan_sections(findings)

    assert {"sql", "ssl", "headers", "xss", "redirect", "takeover"}.issubset(sections.keys())
    assert sections["headers"]["label"] == "HTTP Header Security"
    assert sections["headers"]["status"] == "issues_found"
    assert sections["headers"]["issue_count"] == 1
    assert sections["headers"]["severity_counts"]["Medium"] == 1
    assert sections["headers"]["top_findings"][0]["name"] == "Missing HSTS"
    assert sections["xss"]["recommendations"] == ["Encode output."]


def test_product_sections_include_grouped_findings_and_score_breakdown():
    findings = {
        "accessibility": {
            "status": "issues_found",
            "issues": [
                {
                    "scanner": "accessibility",
                    "title": "Form elements must have labels",
                    "severity": "high",
                    "page_url": "https://example.com",
                    "viewport": "mobile",
                    "selector": "#search",
                    "evidence": {"rule_id": "label", "description": "Input has no label."},
                },
                {
                    "scanner": "accessibility",
                    "title": "Form elements must have labels",
                    "severity": "high",
                    "page_url": "https://example.com/shop",
                    "viewport": "desktop",
                    "selector": "#header-search",
                    "evidence": {"rule_id": "label", "description": "Input has no label."},
                },
            ],
        },
        "app_controls": {
            "status": "issues_found",
            "issues": [{
                "scanner": "app_controls",
                "title": "Protected path is reachable without authentication",
                "severity": "high",
                "page_url": "https://example.com/admin",
                "viewport": "server",
                "evidence": {"rule_id": "protected-path-public", "description": "Admin returned 200."},
            }],
        },
    }

    summary = build_scan_summary(findings)
    sections = build_scan_sections(findings)

    assert summary["score_breakdown"]["security_readiness"]["label"] == "Security Readiness Score"
    assert sections["accessibility"]["groups"][0]["count"] == 2
    assert sections["accessibility"]["groups"][0]["owner"] == "Frontend/UI"
    assert sections["app_controls"]["groups"][0]["fix_effort"] == "Needs backend review"


def test_report_json_endpoint_preserves_contract_and_backfills_summary(auth_client, user, app):
    with app.app_context():
        scan = ScanResult(
            url="https://example.com",
            findings={
                "url": "https://example.com",
                "xss": {
                    "status": "issues_found",
                    "issues": [{"name": "Reflected XSS", "type": "Reflected XSS", "severity": "High"}],
                },
                "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            },
            report_path="",
            user_id=user.id,
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.public_id

    response = auth_client.get(f"/report/{scan_id}?format=json")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["scan_id"] == scan_id
    assert data["summary"]["vulnerable"] is True
    assert data["meta"]["target_url"] == "https://example.com"
    assert "security_score" in data["meta"]
    assert "xss" in data["sections"]
    assert isinstance(data["best_practices"], list)


def test_pdf_report_renders_preproduction_control_evidence_tables():
    findings = {
        "url": "https://example.com",
        "scan_profile": "product_readiness",
        "scan_config": {
            "enable_active_checks": True,
            "active_check_budget": 8,
            "auth_test_accounts": [{"email": "user@example.com", "password": "redacted"}],
            "protected_paths": ["/dashboard"],
            "idor_paths": ["/api/users/123"],
        },
        "app_controls": {
            "status": "issues_found",
            "issues": [{
                "title": "Protected path is reachable without authentication",
                "severity": "high",
                "confidence": "measured",
                "evidence": {"description": "/dashboard returned HTTP 200."},
            }],
            "discovered_endpoints": ["https://example.com/api/users", "https://example.com/api/admin"],
            "javascript_files": [{"url": "https://example.com/app.js", "endpoints": ["https://example.com/api/users"]}],
            "openapi_specs": [{"url": "https://example.com/openapi.json", "endpoint_count": 2}],
            "form_matrix": [{"selector": "#login", "classification": "auth", "method": "POST", "safe_to_submit": True}],
        },
        "abuse_controls": {
            "status": "issues_found",
            "issues": [{
                "title": "No rate limiting observed on active endpoint",
                "severity": "high",
                "confidence": "measured",
                "evidence": {"description": "POST /login accepted 8 requests."},
            }],
            "discovery": {"routes": [{"path": "/login", "kind": "auth", "status_code": 200}]},
            "observations": [{"endpoint": "POST /login", "method": "POST", "requests_sent": 8, "control_detected": False}],
        },
        "broken_links": {
            "status": "issues_found",
            "issues": [{
                "title": "Broken link detected",
                "severity": "medium",
                "confidence": "measured",
                "evidence": {"description": "Link target failed."},
            }],
            "checked_links": [
                {"source_url": "https://example.com", "target_url": "https://example.com/missing", "status_code": 404, "ok": False, "reason": "HTTP 404"}
            ],
        },
        "exposed_services": {
            "status": "issues_found",
            "issues": [{
                "title": "Redis service is publicly reachable",
                "severity": "high",
                "confidence": "measured",
                "evidence": {"description": "TCP port 6379 accepted a connection."},
            }],
            "open_services": [{"host": "example.com", "port": 6379, "protocol": "tcp", "risk": "high", "http": {}}],
            "ports_checked": [80, 443, 6379],
        },
    }
    findings["summary"] = build_scan_summary(findings)
    findings["sections"] = build_scan_sections(findings)

    pdf = generate_report(findings)

    assert pdf.getbuffer().nbytes > 1000
