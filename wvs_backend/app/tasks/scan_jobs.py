from __future__ import annotations

from datetime import datetime
from typing import Any

from app import celery, db
from app.models import ScanJob
from app.settings import settings
from app.utils.scan_pipeline import build_full_scan, persist_scan_result, tag_malicious_result

_TIMEOUT = max(settings.max_scan_time, 60)


@celery.task(
    bind=True,
    name='app.tasks.run_full_scan_job',
    soft_time_limit=_TIMEOUT,
    time_limit=_TIMEOUT + 30,
)
def run_full_scan_job(self, job_id: int) -> dict:
    from celery.exceptions import SoftTimeLimitExceeded

    progress_logs: list[dict[str, Any]] = []
    total_steps = 12

    def store_progress_snapshot(snapshot: dict[str, Any]) -> None:
        progress_job = ScanJob.query.get(job_id)
        if not progress_job:
            return

        current_findings = progress_job.findings if isinstance(progress_job.findings, dict) else {}
        progress_job.findings = {
            **current_findings,
            '_progress': snapshot,
        }
        db.session.commit()

    def push_progress(update: dict[str, Any]) -> None:
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'stage': update['stage'],
            'step_key': update['step_key'],
            'step_label': update['step_label'],
            'step_index': update['step_index'],
            'total_steps': update['total_steps'],
            'percent': update['percent'],
            'message': update['message'],
        }
        progress_logs.append(entry)
        snapshot = {
            'task_state': 'PROGRESS',
            'current_step': update['step_key'],
            'current_step_label': update['step_label'],
            'step_index': update['step_index'],
            'total_steps': update['total_steps'],
            'percent': update['percent'],
            'message': update['message'],
            'logs': progress_logs[-50:],
        }
        store_progress_snapshot(snapshot)
        self.update_state(
            state='PROGRESS',
            meta=snapshot,
        )

    job = ScanJob.query.get(job_id)
    if not job:
        raise ValueError(f"Scan job {job_id} not found")

    try:
        job.status = 'running'
        job.started_at = datetime.utcnow()
        db.session.commit()

        push_progress(
            {
                'stage': 'running',
                'step_key': 'queue',
                'step_label': 'Preparing scan',
                'step_index': 0,
                'total_steps': total_steps,
                'percent': 0,
                'message': 'Preparing scan pipeline',
            }
        )

        findings = build_full_scan(job.url, progress_callback=push_progress)
        tag_malicious_result(job.url, findings)
        push_progress(
            {
                'stage': 'running',
                'step_key': 'report',
                'step_label': 'Saving report',
                'step_index': total_steps,
                'total_steps': total_steps,
                'percent': 100,
                'message': 'Saving scan report',
            }
        )
        result = persist_scan_result(job.url, findings, job.user_id, prefix="scan")

        job.findings = findings
        job.result_id = result.id
        job.status = 'completed'
        job.completed_at = datetime.utcnow()
        job.error_message = None
        db.session.commit()

        push_progress(
            {
                'stage': 'completed',
                'step_key': 'report',
                'step_label': 'Saving report',
                'step_index': total_steps,
                'total_steps': total_steps,
                'percent': 100,
                'message': 'Scan completed',
            }
        )

        return {'job_id': job.public_id, 'status': job.status, 'result_id': result.public_id}

    except SoftTimeLimitExceeded:
        db.session.rollback()
        job = ScanJob.query.get(job_id)
        if job:
            job.status = 'failed'
            job.error_message = f'Scan timed out after {_TIMEOUT}s'
            job.completed_at = datetime.utcnow()
            current_findings = job.findings if isinstance(job.findings, dict) else {}
            job.findings = {
                **current_findings,
                '_progress': {
                    'task_state': 'FAILURE',
                    'current_step': None,
                    'current_step_label': None,
                    'step_index': None,
                    'total_steps': total_steps,
                    'message': f'Scan timed out after {_TIMEOUT}s',
                    'percent': progress_logs[-1]['percent'] if progress_logs else 0,
                    'logs': progress_logs[-50:],
                },
            }
            db.session.commit()
        raise

    except Exception as exc:
        db.session.rollback()
        job = ScanJob.query.get(job_id)
        if job:
            job.status = 'failed'
            job.error_message = str(exc)
            job.completed_at = datetime.utcnow()
            current_findings = job.findings if isinstance(job.findings, dict) else {}
            job.findings = {
                **current_findings,
                '_progress': {
                    'task_state': 'FAILURE',
                    'current_step': None,
                    'current_step_label': None,
                    'step_index': None,
                    'total_steps': total_steps,
                    'message': str(exc),
                    'percent': progress_logs[-1]['percent'] if progress_logs else 0,
                    'logs': progress_logs[-50:],
                },
            }
            db.session.commit()
        raise
