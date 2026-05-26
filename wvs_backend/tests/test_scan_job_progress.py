from __future__ import annotations

from datetime import datetime, timezone

from app import db
from app.models import ScanJob
from app.routes import scans as scans_routes


def test_serialize_task_progress_uses_stored_snapshot_without_task_id(app, user):
    with app.app_context():
        job = ScanJob(
            url="https://example.com",
            scan_type="full",
            status="running",
            user_id=user.id,
            findings={"_progress": {"percent": 40, "message": "Checking XSS"}},
        )
        db.session.add(job)
        db.session.commit()

        progress = scans_routes._serialize_task_progress(job)

        assert progress == {"percent": 40, "message": "Checking XSS"}


def test_serialize_task_progress_prefers_live_task_snapshot(app, user, monkeypatch):
    with app.app_context():
        job = ScanJob(
            url="https://example.com",
            scan_type="full",
            status="running",
            task_id="task-123",
            user_id=user.id,
            findings={"_progress": {"percent": 10, "message": "Old snapshot"}},
        )
        db.session.add(job)
        db.session.commit()

        monkeypatch.setattr(
            scans_routes,
            "_read_task_result_snapshot",
            lambda task_id: (
                "PROGRESS",
                {
                    "current_step": "xss",
                    "current_step_label": "XSS",
                    "step_index": 7,
                    "total_steps": 12,
                    "percent": 58,
                    "message": "Checking xss",
                    "logs": [{"timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), "message": "Checking xss"}],
                },
            ),
        )

        progress = scans_routes._serialize_task_progress(job)

        assert progress["task_state"] == "PROGRESS"
        assert progress["current_step"] == "xss"
        assert progress["percent"] == 58
        assert progress["message"] == "Checking xss"


def test_sync_scan_job_status_marks_successful_task_complete(app, user, monkeypatch):
    with app.app_context():
        job = ScanJob(
            url="https://example.com",
            scan_type="full",
            status="queued",
            task_id="task-123",
            user_id=user.id,
        )
        db.session.add(job)
        db.session.commit()

        class FakeResult:
            state = "SUCCESS"
            info = {}

        monkeypatch.setattr(scans_routes.celery, "AsyncResult", lambda task_id: FakeResult())

        synced = scans_routes._sync_scan_job_status(job)

        assert synced.status == "completed"
        assert synced.completed_at is not None
