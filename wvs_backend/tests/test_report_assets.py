from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app import db
from app.models import ScanResult


def test_report_json_rewrites_screenshot_paths_to_asset_urls(auth_client, user, app, tmp_path: Path):
    screenshot = tmp_path / "issue.png"
    screenshot.write_bytes(b"fake-image")

    with app.app_context():
        scan = ScanResult(
            url="https://example.com",
            findings={
                "url": "https://example.com",
                "accessibility": {
                    "status": "issues_found",
                    "issues": [{
                        "id": "abc",
                        "title": "Missing label",
                        "severity": "high",
                        "confidence": "measured",
                        "page_url": "https://example.com",
                        "viewport": "mobile",
                        "evidence": {
                            "description": "Input missing label",
                            "screenshot_path": str(screenshot),
                        },
                    }],
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
    evidence = data["findings"]["accessibility"]["issues"][0]["evidence"]
    assert "screenshot_path" not in evidence
    assert evidence["screenshot_url"] == f"/report/{scan_id}/assets/{screenshot.name}"


def test_report_asset_requires_scan_owner(auth_client, user, app, tmp_path: Path):
    screenshot = tmp_path / "issue.png"
    screenshot.write_bytes(b"fake-image")

    with app.app_context():
        scan = ScanResult(
            url="https://example.com",
            findings={
                "accessibility": {
                    "issues": [{
                        "evidence": {"screenshot_path": str(screenshot)},
                    }],
                },
            },
            report_path="",
            user_id=user.id,
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.public_id

    response = auth_client.get(f"/report/{scan_id}/assets/{screenshot.name}")
    assert response.status_code == 200
    assert response.data == b"fake-image"
