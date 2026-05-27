from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func
from sqlalchemy import update as sa_update

from app import celery, db
from app.models import ScanJob
from app.settings import settings
from app.utils.time_utils import utc_now, utc_now_isoformat
from app.utils.scan_pipeline import (
    build_full_launch_audit,
    build_full_scan,
    build_product_readiness_scan,
    persist_scan_result,
    tag_malicious_result,
)

_TIMEOUT = max(settings.max_scan_time, 60)


@celery.task(
    bind=True,
    name='app.tasks.run_full_scan_job',
    soft_time_limit=_TIMEOUT,
    time_limit=_TIMEOUT + 30,
    rate_limit=settings.ux_scan_rate_limit,
)
def run_full_scan_job(self, job_id: int) -> dict:
    from celery.exceptions import SoftTimeLimitExceeded

    progress_logs: list[dict[str, Any]] = []
    # Derived at runtime from the actual pipeline step count; 15 for full_scan,
    # 5 for product_readiness, 19 for full_launch_audit. Default to 15.
    total_steps = 15

    def store_progress_snapshot(snapshot: dict[str, Any]) -> None:
        # Patch only the _progress key via JSON_SET to avoid reading + rewriting
        # the entire findings blob on every progress tick.
        try:
            db.session.execute(
                sa_update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(
                    findings=func.json_set(
                        func.coalesce(ScanJob.findings, func.cast('{}', db.JSON)),
                        '$._progress',
                        func.cast(json.dumps(snapshot), db.JSON),
                    )
                )
            )
            db.session.commit()
        except Exception:
            db.session.rollback()

    def push_progress(update: dict[str, Any]) -> None:
        entry = {
            'timestamp': utc_now_isoformat(),
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

    job = db.session.get(ScanJob, job_id)
    if not job:
        raise ValueError(f"Scan job {job_id} not found")

    try:
        job.status = 'running'
        job.started_at = utc_now()
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

        config = {}
        if isinstance(job.findings, dict):
            config = job.findings.get('_config', {}) or {}

        if job.scan_type == 'product_readiness':
            findings = build_product_readiness_scan(
                job.url,
                page_paths=config.get('page_paths') or [],
                enable_ai_review=bool(config.get('enable_ai_review')),
                page_type=config.get('page_type'),
                progress_callback=push_progress,
            )
        elif job.scan_type == 'full_launch_audit':
            findings = build_full_launch_audit(
                job.url,
                page_paths=config.get('page_paths') or [],
                enable_ai_review=bool(config.get('enable_ai_review')),
                page_type=config.get('page_type'),
                progress_callback=push_progress,
            )
        else:
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
        job.completed_at = utc_now()
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
        job = db.session.get(ScanJob, job_id)
        if job:
            job.status = 'failed'
            job.error_message = f'Scan timed out after {_TIMEOUT}s'
            job.completed_at = utc_now()
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
        job = db.session.get(ScanJob, job_id)
        if job:
            job.status = 'failed'
            job.error_message = str(exc)
            job.completed_at = utc_now()
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
