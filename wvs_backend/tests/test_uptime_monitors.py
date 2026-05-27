from __future__ import annotations

from datetime import timedelta

from app import db
from app.models import UptimeMonitor
from app.services.uptime import monitor_is_due
from app.tasks.uptime import run_due_uptime_checks
from app.utils.time_utils import utc_now


def test_create_and_list_uptime_monitors(auth_client, auth_headers):
    create_response = auth_client.post(
        "/uptime-monitors",
        json={
            "name": "Main Site",
            "target_url": "https://example.com",
            "check_interval_minutes": 5,
        },
        headers=auth_headers,
    )
    assert create_response.status_code == 201
    payload = create_response.get_json()
    assert payload["monitor"]["name"] == "Main Site"
    assert payload["monitor"]["status"] == "pending"

    list_response = auth_client.get("/uptime-monitors", headers=auth_headers)
    assert list_response.status_code == 200
    list_payload = list_response.get_json()
    assert len(list_payload["monitors"]) == 1
    assert list_payload["monitors"][0]["target_url"] == "https://example.com"


def test_manual_uptime_check_updates_monitor_status(app, auth_client, auth_headers, monkeypatch):
    create_response = auth_client.post(
        "/uptime-monitors",
        json={
            "name": "API",
            "target_url": "https://example.com",
            "check_interval_minutes": 5,
        },
        headers=auth_headers,
    )
    monitor_id = create_response.get_json()["monitor"]["id"]

    class FakeResponse:
        status_code = 200

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def get(self, _url):
            return FakeResponse()

    monkeypatch.setattr("app.services.uptime.httpx.Client", lambda **_: FakeClient())

    check_response = auth_client.post(
        f"/uptime-monitors/{monitor_id}/check",
        json={},
        headers=auth_headers,
    )
    assert check_response.status_code == 200
    payload = check_response.get_json()
    assert payload["check"]["status"] == "up"
    assert payload["monitor"]["status"] == "up"
    assert payload["monitor"]["consecutive_failures"] == 0


def test_due_uptime_checks_task_runs_due_monitors(app, user, monkeypatch):
    with app.app_context():
        monitor = UptimeMonitor(
            name="Website",
            target_url="https://example.com",
            check_interval_minutes=5,
            user_id=user.id,
            last_checked_at=utc_now() - timedelta(minutes=10),
        )
        db.session.add(monitor)
        db.session.commit()

        class FakeResponse:
            status_code = 200

        class FakeClient:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def get(self, _url):
                return FakeResponse()

        monkeypatch.setattr("app.services.uptime.httpx.Client", lambda **_: FakeClient())

        assert monitor_is_due(monitor) is True
        result = run_due_uptime_checks()
        assert result["checked"] == 1

        db.session.refresh(monitor)
        assert monitor.status == "up"
        assert monitor.last_checked_at is not None
        assert len(monitor.checks) == 1

