from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app import db
from app.models import VerifiedTarget
from app.routes import scans as scans_routes
from app.utils.scan_helpers import build_scan_sections, build_scan_summary


def test_build_scan_summary_counts_product_readiness_findings():
    findings = {
        "accessibility": {"issues": [{"title": "Missing label", "severity": "high"}], "score": 92},
        "responsive_ux": {"issues": [{"title": "Overflow", "severity": "high"}], "score": 88},
        "performance_ux": {"issues": [{"title": "Slow load", "severity": "medium"}], "score": 76},
        "form_usability": {"issues": [{"title": "Missing submit", "severity": "high"}], "score": 80},
        "visual_ai": {"issues": [{"title": "Weak CTA", "severity": "recommendation"}]},
        "launch_readiness": {"score": 60},
    }

    summary = build_scan_summary(findings)

    assert summary["accessibility_issue_count"] == 1
    assert summary["responsive_issue_count"] == 1
    assert summary["performance_issue_count"] == 1
    assert summary["form_issue_count"] == 1
    assert summary["visual_ai_issue_count"] == 1
    assert summary["launch_blocker_count"] == 3
    assert summary["launch_readiness_score"] == 60


def test_build_scan_sections_includes_product_readiness_sections():
    findings = {
        "accessibility": {
            "status": "issues_found",
            "issues": [{
                "title": "Missing label",
                "severity": "high",
                "confidence": "measured",
                "page_url": "https://example.com",
                "viewport": "mobile",
                "evidence": {"description": "Input has no associated label."},
            }],
            "recommendations": ["Add labels."],
        }
    }

    sections = build_scan_sections(findings)

    assert "accessibility" in sections
    assert sections["accessibility"]["issue_count"] == 1
    assert sections["accessibility"]["top_findings"][0]["name"] == "Missing label"


def test_product_readiness_scan_requires_verified_target_when_enabled(auth_client, auth_headers, app, user, monkeypatch):
    app.config["REQUIRE_VERIFIED_TARGETS"] = True

    response = auth_client.post(
        "/scan",
        json={"url": "https://example.com", "scan_profile": "product_readiness"},
        headers=auth_headers,
    )

    assert response.status_code == 400
    assert "verified target" in response.get_json()["message"].lower()


def test_product_readiness_scan_queues_when_verified_target_exists(auth_client, auth_headers, app, user, monkeypatch):
    app.config["REQUIRE_VERIFIED_TARGETS"] = True

    with app.app_context():
        target = VerifiedTarget(
            user_id=user.id,
            target_url="https://example.com",
            normalized_domain="example.com",
            verification_method="meta_tag",
            verification_token_hash="hash",
            verification_status="verified",
            verified_at=datetime.now(timezone.utc).replace(tzinfo=None),
            token_expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1),
        )
        db.session.add(target)
        db.session.commit()
        target_id = target.public_id

    class FakeTask:
        id = "celery-task-1"

    monkeypatch.setattr(scans_routes.run_full_scan_job, "apply_async", lambda args, queue: FakeTask())

    response = auth_client.post(
        "/scan",
        json={
            "url": "https://example.com",
            "scan_profile": "product_readiness",
            "verified_target_id": target_id,
            "page_paths": ["/", "/signup"],
            "enable_active_checks": True,
            "active_check_paths": ["POST /login"],
            "active_check_budget": 5,
        },
        headers=auth_headers,
    )

    assert response.status_code == 202
    payload = response.get_json()
    assert payload["scan_profile"] == "product_readiness"

    with app.app_context():
        job = scans_routes.ScanJob.query.filter_by(public_id=payload["job_id"]).first()
        assert job is not None
        assert job.scan_type == "product_readiness"
        assert job.findings["_config"]["page_paths"] == ["/", "/signup"]
        assert job.findings["_config"]["enable_active_checks"] is True
        assert job.findings["_config"]["active_check_paths"] == ["POST /login"]
        assert job.findings["_config"]["active_check_budget"] == 5
