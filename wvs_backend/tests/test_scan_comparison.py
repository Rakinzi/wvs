from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app import db
from app.models import ScanResult
from app.services.visual_ai_provider import NoOpVisualAIProvider, build_visual_ai_provider


def test_report_json_includes_previous_scan_comparison(auth_client, user, app):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with app.app_context():
        previous = ScanResult(
            url="https://example.com",
            findings={
                "url": "https://example.com",
                "scan_profile": "product_readiness",
                "accessibility": {
                    "status": "issues_found",
                    "issues": [
                        {
                            "id": "fixed-1",
                            "title": "Form control has no accessible label",
                            "severity": "high",
                            "confidence": "measured",
                            "page_url": "https://example.com/signup",
                            "viewport": "mobile",
                            "selector": "#email",
                            "evidence": {"description": "Input missing label."},
                        },
                        {
                            "id": "persist-1",
                            "title": "Tap target is too small on mobile",
                            "severity": "medium",
                            "confidence": "measured",
                            "page_url": "https://example.com/signup",
                            "viewport": "mobile",
                            "selector": "#submit",
                            "evidence": {"description": "Button is 30x30."},
                        },
                    ],
                    "score": 70,
                },
                "launch_readiness": {"score": 70},
                "timestamp": (now - timedelta(days=1)).isoformat(),
            },
            report_path="",
            user_id=user.id,
            timestamp=now - timedelta(days=1),
        )
        current = ScanResult(
            url="https://example.com",
            findings={
                "url": "https://example.com",
                "scan_profile": "product_readiness",
                "accessibility": {
                    "status": "issues_found",
                    "issues": [
                        {
                            "id": "persist-1",
                            "title": "Tap target is too small on mobile",
                            "severity": "medium",
                            "confidence": "measured",
                            "page_url": "https://example.com/signup",
                            "viewport": "mobile",
                            "selector": "#submit",
                            "evidence": {"description": "Button is 30x30."},
                        },
                        {
                            "id": "new-1",
                            "title": "Document language is missing",
                            "severity": "high",
                            "confidence": "measured",
                            "page_url": "https://example.com/",
                            "viewport": "desktop",
                            "selector": "html",
                            "evidence": {"description": "Missing lang attribute."},
                        },
                    ],
                    "score": 62,
                },
                "launch_readiness": {"score": 62},
                "timestamp": now.isoformat(),
            },
            report_path="",
            user_id=user.id,
            timestamp=now,
        )
        db.session.add_all([previous, current])
        db.session.commit()
        current_id = current.public_id
        previous_id = previous.public_id

    response = auth_client.get(f"/report/{current_id}?format=json")

    assert response.status_code == 200
    data = response.get_json()
    assert data["comparison"]["previous_scan_id"] == previous_id
    assert data["comparison"]["fixed_count"] == 1
    assert data["comparison"]["new_count"] == 1
    assert data["comparison"]["unresolved_count"] == 1
    assert data["comparison"]["summary_delta"]["launch_readiness_score"] == -8


def test_visual_ai_provider_defaults_to_noop():
    provider = build_visual_ai_provider()
    assert isinstance(provider, NoOpVisualAIProvider)
    assert provider.is_available() is False
