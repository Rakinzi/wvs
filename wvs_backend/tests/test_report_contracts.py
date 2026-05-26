from __future__ import annotations

from datetime import datetime, timezone

from app import db
from app.models import ScanResult
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
