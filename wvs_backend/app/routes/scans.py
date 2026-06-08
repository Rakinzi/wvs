import os
import copy
from pathlib import Path

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse

from app.auth import current_user
from app.models import ScanJob, ScanResult, VerifiedTarget, ROLE_SCAN_LIMITS
from app.settings import settings
from app.scanners import SecurityScanner
from app.schemas import ScanRequestPayload
from app.utils.db_manager import DBManager
from app.utils.scan_helpers import (
    build_best_practices,
    build_report_meta,
    build_scan_sections,
    build_scan_summary,
    normalize_target_url,
)
from app.utils.scan_comparison import build_scan_comparison
from app.utils.reports import generate_report
from app.utils.ux_screenshot_manager import collect_screenshot_paths
from app import db, init_celery, limiter
from app.config import get_config
from pydantic import ValidationError
from app.utils.time_utils import utc_now, utc_now_isoformat

router = APIRouter()
# bp alias kept for celery task imports that reference scans.bp transitionally
bp = router


class _CeleryProxy:
    def _app(self):
        if celery: return celery
        cfg = get_config()
        return init_celery({k: v for cls in reversed(cfg.__mro__) for k, v in vars(cls).items() if k.isupper()})

    def AsyncResult(self, *args, **kwargs):
        return self._app().AsyncResult(*args, **kwargs)


class _RunFullScanJobProxy:
    def _task(self):
        from app.tasks.scan_jobs import run_full_scan_job as task

        return task

    def apply_async(self, *args, **kwargs):
        return self._task().apply_async(*args, **kwargs)


celery = _CeleryProxy()
run_full_scan_job = _RunFullScanJobProxy()


def _celery_app():
    celery._app()
    return celery


def _security_scanner():
    return SecurityScanner()


def _scan_pipeline():
    from app.utils.scan_pipeline import attach_launch_verdict, persist_scan_result

    return attach_launch_verdict, persist_scan_result


def persist_scan(user, findings, prefix="scan"):
    attach_launch_verdict, persist_scan_result = _scan_pipeline()
    if 'launch_verdict' not in findings:
        attach_launch_verdict(findings)
    return persist_scan_result(findings["url"], findings, user.id, prefix=prefix)


def _check_scan_quota(user) -> tuple[bool, str]:
    """Return (allowed, error_message). Counts scans started in the last hour."""
    limit = user.scan_limit
    if limit is None:
        return True, ''
    from datetime import timedelta
    window_start = utc_now() - timedelta(hours=1)
    recent = ScanJob.query.filter(
        ScanJob.user_id == user.id,
        ScanJob.created_at >= window_start,
    ).count()
    if recent >= limit:
        return False, f'Scan limit reached ({limit}/hour for {user.role} plan). Upgrade to run more scans.'
    return True, ''


def _preflight(user, url: str) -> None:
    """Run all pre-scan security gates. Raises HTTPException on any failure."""
    if not user.email_verified:
        raise HTTPException(403, "Email address must be verified before scanning")

    allowed, quota_msg = _check_scan_quota(user)
    if not allowed:
        raise HTTPException(429, quota_msg)

    is_malicious, reason = DBManager.check_malicious_url(url)
    if is_malicious:
        raise HTTPException(400, f"URL is flagged as malicious: {reason}")


def _find_verified_target(u, url: str, verified_target_id: str | None = None):
    normalized = normalize_target_url(url)
    hostname = normalized.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    query = VerifiedTarget.query.filter_by(user_id=u.id, verification_status="verified")
    if verified_target_id:
        query = query.filter_by(public_id=verified_target_id)

    for candidate in query.all():
        if candidate.normalized_domain.lower() == hostname:
            return candidate

    return None


def _ensure_verified_target(
    u,
    url: str,
    verified_target_id: str | None,
    *,
    message: str = "A verified target is required for this scan profile",
):
    target = _find_verified_target(u, url, verified_target_id)
    if target:
        return target

    raise ValueError(message)


def _ensure_active_checks_authorized(u, url: str, verified_target_id: str | None) -> None:
    _ensure_verified_target(
        u,
        url,
        verified_target_id,
        message="Active checks require verified target ownership before they can run.",
    )


def _resolve_job_failure_message(task_result) -> str:
    try:
        info = task_result.info
    except Exception:
        return "Scan job failed in Celery worker."

    if info is None:
        return "Scan job failed in Celery worker."

    text = str(info).strip()
    if not text:
        return "Scan job failed in Celery worker."

    lowered = text.lower()
    if "timelimitexceeded" in lowered or "time limit" in lowered:
        return "Scan timed out in Celery worker."
    if "workerlosterror" in lowered or "worker exited prematurely" in lowered:
        return "Scan worker exited unexpectedly."
    return text


def _read_task_result_snapshot(task_id: str) -> tuple[str | None, dict]:
    task_result = _celery_app().AsyncResult(task_id)

    try:
        state = task_result.state
        info = task_result.info if isinstance(task_result.info, dict) else {}
    except Exception:
        return None, {}

    return state, info


def _progress_last_seen_at(progress: dict | None):
    if not isinstance(progress, dict):
        return None

    logs = progress.get('logs') if isinstance(progress.get('logs'), list) else []
    candidates = []
    if isinstance(progress.get('timestamp'), str):
        candidates.append(progress['timestamp'])
    for entry in reversed(logs):
        if isinstance(entry, dict) and isinstance(entry.get('timestamp'), str):
            candidates.append(entry['timestamp'])
            break

    for value in candidates:
        try:
            return utc_now().__class__.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
        except ValueError:
            continue
    return None


def _progress_stale_seconds(progress: dict | None) -> int | None:
    last_seen_at = _progress_last_seen_at(progress)
    if not last_seen_at:
        return None
    return max(0, int((utc_now() - last_seen_at).total_seconds()))


def _decorate_progress(job: ScanJob, progress: dict | None) -> dict | None:
    if not isinstance(progress, dict):
        return progress

    stale_after_seconds = 120
    stale_seconds = _progress_stale_seconds(progress)
    decorated = dict(progress)
    if job.status in {"queued", "running"} and stale_seconds is not None and stale_seconds >= stale_after_seconds:
        decorated["stale"] = True
        decorated["stale_seconds"] = stale_seconds
        decorated["message"] = "The worker has not reported progress recently."
    else:
        decorated["stale"] = False
        decorated["stale_seconds"] = stale_seconds
    return decorated


def _serialize_task_progress(job: ScanJob) -> dict | None:
    stored_progress = None
    if isinstance(job.findings, dict):
        candidate = job.findings.get('_progress')
        if isinstance(candidate, dict):
            stored_progress = candidate

    if not job.task_id:
        return stored_progress

    task_state, info = _read_task_result_snapshot(job.task_id)
    logs = info.get('logs') if isinstance(info.get('logs'), list) else []

    if not info and stored_progress:
        return _decorate_progress(job, stored_progress)

    if not info and task_state is None:
        if job.status == "failed":
            return {
                'task_state': 'FAILURE',
                'current_step': None,
                'current_step_label': None,
                'step_index': None,
                'total_steps': None,
                'percent': stored_progress.get('percent') if stored_progress else None,
                'message': job.error_message or "Scan job failed in Celery worker.",
                'logs': stored_progress.get('logs') if stored_progress else [],
            }
        return _decorate_progress(job, stored_progress)

    return _decorate_progress(job, {
        'task_state': task_state,
        'current_step': info.get('current_step'),
        'current_step_label': info.get('current_step_label'),
        'step_index': info.get('step_index'),
        'total_steps': info.get('total_steps'),
        'percent': info.get('percent'),
        'message': info.get('message'),
        'logs': logs,
    })


def _safe_commit() -> bool:
    try:
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _sync_scan_job_status(job: ScanJob) -> ScanJob:
    if job.status not in {"queued", "running"} or not job.task_id:
        return job

    task_result = _celery_app().AsyncResult(job.task_id)
    try:
        task_state = task_result.state
    except Exception:
        job.status = "failed"
        job.completed_at = utc_now()
        if not job.error_message:
            progress = _serialize_task_progress(job) or {}
            job.error_message = progress.get("message") or "Scan job failed in Celery worker."
        _safe_commit()
        return job

    current_progress = _serialize_task_progress(job) or {}
    stale_seconds = current_progress.get("stale_seconds") if isinstance(current_progress, dict) else None
    stale_failure_seconds = int(int(getattr(settings, "max_scan_time", 900))) + 120
    if job.status == "running" and isinstance(stale_seconds, int) and stale_seconds >= stale_failure_seconds:
        job.status = "failed"
        job.completed_at = utc_now()
        job.error_message = (
            "Scan worker stopped reporting progress. The job was likely interrupted; please start a new scan."
        )
        current_findings = job.findings if isinstance(job.findings, dict) else {}
        progress = current_findings.get("_progress", {}) if isinstance(current_findings, dict) else {}
        job.findings = {
            **current_findings,
            "_progress": {
                **progress,
                "task_state": "FAILURE",
                "message": job.error_message,
                "stale": True,
                "stale_seconds": stale_seconds,
            },
        }
        _safe_commit()
        return job

    if task_state in {"PENDING", "RECEIVED", "STARTED"}:
        return job

    if task_state == "PROGRESS":
        if job.status != "running":
            job.status = "running"
            _safe_commit()
        return job

    if task_state == "RETRY":
        job.status = "queued"
        job.completed_at = None
        job.error_message = None
        current_findings = job.findings if isinstance(job.findings, dict) else {}
        progress = current_findings.get("_progress", {}) if isinstance(current_findings, dict) else {}
        job.findings = {
            **current_findings,
            "_progress": {
                **progress,
                "task_state": "RETRY",
                "message": "Worker restarted. Waiting for Celery to retry this scan.",
            },
        }
        _safe_commit()
        return job

    if task_state == "SUCCESS":
        if job.status != "completed":
            job.status = "completed"
            if not job.completed_at:
                job.completed_at = utc_now()
            _safe_commit()
        return job

    if task_state in {"FAILURE", "REVOKED"}:
        job.status = "failed"
        job.completed_at = utc_now()
        if not job.error_message:
            job.error_message = _resolve_job_failure_message(task_result)
        _safe_commit()
        return job

    try:
        task_result.get(timeout=0)
    except Exception as exc:
        if exc.__class__.__name__ == "TimeoutError":
            return job
        job.status = "failed"
        job.completed_at = utc_now()
        if not job.error_message:
            job.error_message = _resolve_job_failure_message(task_result)
        _safe_commit()
        return job

    return job


def _asset_url(scan_id: str, filename: str) -> str:
    return f"/report/{scan_id}/assets/{filename}"


def _safe_existing_file(path: str | None, base_dir: str, *, suffix: str | None = None) -> str | None:
    if not path:
        return None

    try:
        resolved_base = Path(base_dir).resolve()
        resolved_path = Path(path).resolve()
        resolved_path.relative_to(resolved_base)
    except (OSError, ValueError):
        return None

    if suffix and resolved_path.suffix.lower() != suffix:
        return None
    if not resolved_path.is_file():
        return None
    return str(resolved_path)


def _safe_report_cache_path(scan: ScanResult) -> str | None:
    return _safe_existing_file(scan.report_path, settings.report_folder, suffix=".pdf")


def _publicize_scan_assets(scan_id: str, payload):
    if isinstance(payload, dict):
        cloned = {}
        for key, value in payload.items():
            if key == "evidence" and isinstance(value, dict):
                evidence = dict(value)
                screenshot_path = evidence.pop("screenshot_path", None)
                if isinstance(screenshot_path, str) and screenshot_path:
                    evidence["screenshot_url"] = _asset_url(scan_id, os.path.basename(screenshot_path))
                cloned[key] = _publicize_scan_assets(scan_id, evidence)
            elif key == "screenshots" and isinstance(value, dict) and "screenshots" in value:
                # Convert screenshot_scanner paths {desktop: path, mobile: path} → URLs
                raw = value.get("screenshots") or {}
                cloned[key] = {
                    "status": value.get("status"),
                    "screenshots": {
                        vp: _asset_url(scan_id, os.path.basename(path))
                        for vp, path in raw.items()
                        if isinstance(path, str) and path
                    },
                }
            else:
                cloned[key] = _publicize_scan_assets(scan_id, value)
        return cloned
    if isinstance(payload, list):
        return [_publicize_scan_assets(scan_id, item) for item in payload]
    return payload


def _infer_scan_profile(findings: dict) -> str:
    return str((findings or {}).get("scan_profile") or "security_only")


def _find_previous_scan_for_comparison(scan: ScanResult) -> ScanResult | None:
    current_profile = _infer_scan_profile(scan.findings or {})
    candidates = (
        ScanResult.query.filter(
            ScanResult.user_id == scan.user_id,
            ScanResult.url == scan.url,
            ScanResult.timestamp < scan.timestamp,
        )
        .order_by(ScanResult.timestamp.desc())
        .limit(25)
        .all()
    )
    for candidate in candidates:
        if _infer_scan_profile(candidate.findings or {}) == current_profile:
            return candidate
    return candidates[0] if candidates else None

@router.post("/scan")
async def start_scan(request: Request, user: Annotated['User', Depends(current_user)]):
    try:

        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        scan_profile = payload.scan_profile or 'security_only'

        _preflight(user, url)

        verified_target = None
        if settings.require_verified_targets:
            verified_target = _ensure_verified_target(user, url, payload.verified_target_id)
        elif payload.enable_active_checks:
            verified_target = _ensure_verified_target(
                user,
                url,
                payload.verified_target_id,
                message="Active checks require verified target ownership before they can run.",
            )
        
        job = ScanJob(
            url=url,
            scan_type=scan_profile,
            status='queued',
            user_id=user.id,
            findings={
                '_config': {
                    'page_paths': payload.page_paths,
                    'page_type': payload.page_type,
                    'enable_ai_review': payload.enable_ai_review,
                    'enable_active_checks': payload.enable_active_checks,
                    'active_check_paths': payload.active_check_paths,
                    'active_check_budget': payload.active_check_budget,
                    'auth_test_accounts': [account.model_dump() for account in payload.auth_test_accounts],
                    'protected_paths': payload.protected_paths,
                    'idor_paths': payload.idor_paths,
                    'verified_target_id': verified_target.public_id if verified_target else payload.verified_target_id,
                    'verified_domain': verified_target.normalized_domain if verified_target else None,
                    'active_checks_authorized': bool(payload.enable_active_checks and verified_target),
                }
            },
        )
        db.session.add(job)
        db.session.commit()

        try:
            queue_name = settings.ux_scan_queue if scan_profile in {"product_readiness", "full_launch_audit"} else settings.security_scan_queue
            _celery_app()
            task = run_full_scan_job.apply_async(args=[job.id], queue=queue_name)
            job.task_id = task.id
            db.session.commit()
        except Exception as exc:
            job.status = 'failed'
            job.error_message = f'Failed to queue scan job: {exc}'
            job.completed_at = utc_now()
            db.session.commit()
            return JSONResponse(content={
                'status': 'error',
                'message': 'Failed to queue scan job. Check Celery broker connectivity.',
            }, status_code=503)

        return {
            'status': 'accepted',
            'job_id': job.public_id,
            'task_id': task.id,
            'url': url,
            'scan_profile': scan_profile,
            'message': 'Scan queued successfully',
            'timestamp': job.created_at.isoformat()
        }
        
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        db.session.rollback()
        return JSONResponse(content={
            'status': 'error',
            'message': str(e)
        }, status_code=500)

@router.post("/scan/sqli")
async def check_sql_injection(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)
        
        if payload.enable_active_checks:
            _ensure_active_checks_authorized(user, url, payload.verified_target_id)

        # Perform the scan synchronously
        scanner = _security_scanner()
        results = scanner.check_sql_injection(url, enable_active_checks=payload.enable_active_checks)
        
        # Generate recommendations based on findings
        recommendations = []
        if results:
            recommendations.append("Implement prepared statements or parameterized queries")
            recommendations.append("Use input validation and sanitization")
            recommendations.append("Apply the principle of least privilege for database users")
            recommendations.append("Consider implementing a Web Application Firewall (WAF)")
        
        # Create findings object
        findings = {
            'url': url,
            'sqli': results or [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'timestamp': utc_now_isoformat()
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)
        
        scan = persist_scan(user, findings, prefix="sqli_scan")
        
        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'vulnerable': findings['summary']['vulnerable'],
            'summary': findings['summary'],
        }
        
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        return JSONResponse(content={
            'status': 'error',
            'message': str(e)
        }, status_code=500)

@router.post("/scan/ssl")
async def check_ssl(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)
        
        scanner = _security_scanner()
        results = scanner.check_ssl(url)
        
        # Generate recommendations based on findings
        recommendations = []
        if not results.get('valid', False):
            recommendations.append("Obtain a valid SSL/TLS certificate from a trusted CA")
            recommendations.append("Ensure proper installation and configuration of SSL/TLS")
            recommendations.append("Use strong cipher suites and protocols (TLS 1.2+)")
        elif results.get('self_signed', False):
            recommendations.append("Replace self-signed certificate with one from a trusted CA")
        
        # Create findings object
        findings = {
            'url': url,
            'sqli': [],
            'ssl': results,
            'headers': scanner.check_headers(url),
            'wordpress': scanner.check_wordpress(url),
            'zap': scanner.check_zap(url),
            'malicious': {'is_malicious': False},
            'timestamp': utc_now_isoformat()
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)
        recommendations.extend(findings['headers'].get('recommendations', []))
        recommendations.extend(findings['wordpress'].get('recommendations', []))
        recommendations = list(dict.fromkeys(recommendations))
        
        scan = persist_scan(user, findings, prefix="ssl_scan")
        
        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'header_findings': findings['headers'],
            'wordpress_findings': findings['wordpress'],
            'summary': findings['summary'],
        }
        
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        return JSONResponse(content={
            'status': 'error',
            'message': str(e)
        }, status_code=500)


@router.post("/scan/wordpress")
async def check_wordpress(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        if payload.enable_active_checks:
            _ensure_active_checks_authorized(user, url, payload.verified_target_id)

        scanner = _security_scanner()
        results = scanner.check_wordpress(url, enable_active_checks=payload.enable_active_checks)
        recommendations = list(results.get('recommendations', []))

        findings = {
            'url': url,
            'sqli': [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': results,
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'timestamp': utc_now_isoformat()
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="wordpress_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        return JSONResponse(content={
            'status': 'error',
            'message': str(e)
        }, status_code=500)


@router.get("/scan/jobs/{job_id}")
def get_scan_job(job_id: str, user: Annotated['User', Depends(current_user)]):

    job = ScanJob.query.filter_by(public_id=job_id).first_or_404()
    if job.user_id != user.id and not user.is_admin:
        raise HTTPException(403, 'Unauthorized')
    job = _sync_scan_job_status(job)

    payload = job.to_dict()
    payload['scan_id'] = job.result.public_id if job.result else None
    payload['has_vulnerabilities'] = bool(
        (job.findings or {}).get('summary', {}).get('vulnerable', False)
    )
    payload['progress'] = _serialize_task_progress(job)
    return {
        'status': 'success',
        'job': payload,
    }


@router.get("/scan/jobs")
def list_scan_jobs(user: Annotated['User', Depends(current_user)], limit: int = Query(default=20, ge=1, le=100), request: Request = None):

    limit = request.args.get('limit', 20, type=int)
    job_ids = [
        row.id
        for row in ScanJob.query.with_entities(ScanJob.id)
        .filter(ScanJob.user_id == user.id)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
        .all()
    ]
    order = {job_id: index for index, job_id in enumerate(job_ids)}
    jobs = ScanJob.query.filter(ScanJob.id.in_(job_ids)).all() if job_ids else []
    jobs = sorted(jobs, key=lambda job: order.get(job.id, len(order)))
    jobs = [_sync_scan_job_status(job) for job in jobs]

    return {
        'status': 'success',
        'jobs': [
            {
                **job.to_dict(),
                'progress': _serialize_task_progress(job),
            }
            for job in jobs
        ],
    }

@router.get("/report/{scan_id}")
async def get_report(scan_id: str, request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        
        scan = ScanResult.query.filter_by(public_id=scan_id).first_or_404()
        
        # Check if user owns the scan or is admin
        if scan.user_id != user.id and not user.is_admin:
            raise HTTPException(403, 'Unauthorized access to report')
        
        report_format = (request.query_params.get('format') or 'pdf').lower()
        findings = scan.findings or {}
        if 'summary' not in findings:
            findings['summary'] = build_scan_summary(findings)
        if 'sections' not in findings:
            findings['sections'] = build_scan_sections(findings)
        if 'launch_verdict' not in findings:
            attach_launch_verdict, _ = _scan_pipeline()
            attach_launch_verdict(findings)

        if report_format == 'json':
            attach_launch_verdict, _ = _scan_pipeline()
            public_findings = _publicize_scan_assets(scan.public_id, copy.deepcopy(findings))
            public_findings['summary'] = build_scan_summary(public_findings)
            public_findings['sections'] = build_scan_sections(public_findings)
            attach_launch_verdict(public_findings)
            summary = public_findings.get('summary', {})
            comparison = None
            previous_scan = _find_previous_scan_for_comparison(scan)
            if previous_scan is not None:
                previous_findings = previous_scan.findings or {}
                comparison = build_scan_comparison(public_findings, _publicize_scan_assets(previous_scan.public_id, copy.deepcopy(previous_findings)))
                comparison["previous_scan_id"] = previous_scan.public_id
                comparison["previous_timestamp"] = previous_scan.timestamp.isoformat()
            return {
                'status': 'success',
                'scan_id': scan.public_id,
                'url': scan.url,
                'timestamp': scan.timestamp.isoformat(),
                'scan_profile': _infer_scan_profile(public_findings),
                'meta': build_report_meta(scan.public_id, scan.url, scan.timestamp.isoformat(), summary),
                'summary': summary,
                'sections': public_findings.get('sections', {}),
                'best_practices': build_best_practices(public_findings),
                'findings': public_findings,
                'comparison': comparison,
            }

        if report_format == 'sbom':
            return {
                'status': 'success',
                'sbom': {
                    'scan_id': scan.public_id,
                    'url': scan.url,
                    'timestamp': scan.timestamp.isoformat(),
                    'packages': (findings.get('tech') or {}).get('packages', []),
                    'advisories': (findings.get('tech') or {}).get('advisories', []),
                    'best_practices': build_best_practices(findings),
                },
            }

        try:
            tz_offset = int(request.query_params.get('tz_offset') or 0)
        except ValueError:
            tz_offset = 0

        # Serve cached PDF when one exists and tz_offset matches (avoids rebuilding on every download)
        cached_path = _safe_report_cache_path(scan)
        if cached_path and tz_offset == 0:
            return FileResponse(
                cached_path,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'scan_{scan.id}_report.pdf',
            )

        report_data = {
            'scan_id':   scan.public_id,
            'url':       scan.url,
            'timestamp': scan.timestamp.isoformat(),
            'tz_offset': tz_offset,
            **findings,
        }
        pdf_buffer = generate_report(report_data)

        # Cache to disk if we have a reports dir
        write_path = scan.report_path
        if write_path:
            try:
                resolved_reports = Path(settings.report_folder).resolve()
                resolved_write_path = Path(write_path).resolve()
                resolved_write_path.relative_to(resolved_reports)
                if resolved_write_path.suffix.lower() != ".pdf":
                    raise OSError("Refusing to cache report outside PDF path")
                os.makedirs(resolved_write_path.parent, exist_ok=True)
                with open(resolved_write_path, 'wb') as f:
                    f.write(pdf_buffer.getbuffer())
                pdf_buffer.seek(0)
            except (OSError, ValueError):
                pdf_buffer.seek(0)

        return FileResponse(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'scan_{scan.id}_report.pdf',
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, str(e))


@router.get("/report/{scan_id}/assets/{asset_name}")
def get_report_asset(scan_id: str, asset_name: str, user: Annotated['User', Depends(current_user)]):

    scan = ScanResult.query.filter_by(public_id=scan_id).first_or_404()
    if scan.user_id != user.id and not user.is_admin:
        raise HTTPException(403, 'Unauthorized access to report assets')

    screenshot_paths = collect_screenshot_paths(scan.findings or {})
    allowed = {os.path.basename(path): path for path in screenshot_paths}
    target_path = _safe_existing_file(allowed.get(asset_name), settings.ux_scan_screenshot_dir, suffix=".png")
    if not target_path and getattr(settings, "testing", False):
        target_path = _safe_existing_file(allowed.get(asset_name), "/", suffix=".png")
    if not target_path:
        raise HTTPException(404, 'Asset not found')

    return FileResponse(target_path, media_type="image/png")

@router.get("/scans/history")
def get_scan_history(user: Annotated['User', Depends(current_user)], limit: int = Query(default=20, ge=1, le=200), request: Request = None):
    try:
            
        scans = DBManager.get_user_scans(user.id, limit)
        
        results = []
        for scan in scans:
            findings = scan.findings or {}
            summary = findings.get('summary') or build_scan_summary(findings)
            results.append({
                'id': scan.public_id,
                'url': scan.url,
                'timestamp': scan.timestamp.isoformat(),
                'scan_profile': _infer_scan_profile(findings),
                'has_vulnerabilities': summary.get('vulnerable', False),
                'issue_count': summary.get('total_issues', 0),
            })
        
        return {
            'status': 'success',
            'scans': results
        }
        
    except Exception as e:
        return JSONResponse(content={
            'status': 'error',
            'message': str(e)
        }, status_code=500)

@router.post("/scan/xss")
async def check_xss(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_xss(url)

        recommendations = []
        if results.get('reflected_xss_count', 0) > 0:
            recommendations.append("Encode all user-supplied output using context-aware encoding (HTML, JS, URL).")
            recommendations.append("Implement a strict Content-Security-Policy header.")
            recommendations.append("Use HttpOnly and Secure flags on session cookies.")
        if not results.get('csp_present'):
            recommendations.append("Add a Content-Security-Policy header even if no XSS was found.")

        findings = {
            'url': url,
            'sqli': [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'xss': results,
            'timestamp': utc_now_isoformat()
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="xss_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'vulnerable': results.get('reflected_xss_count', 0) > 0,
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/tech")
async def check_tech(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_tech(url)

        findings = {
            'url': url,
            'sqli': [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'tech': results,
            'timestamp': utc_now_isoformat()
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="tech_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'technologies': results.get('technologies', {}),
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/exposure")
async def check_exposure(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        if payload.enable_active_checks:
            _ensure_active_checks_authorized(user, url, payload.verified_target_id)

        scanner = _security_scanner()
        results = scanner.check_exposure(url, enable_active_checks=payload.enable_active_checks)

        findings = {
            'url': url,
            'sqli': [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'exposure': results,
            'timestamp': utc_now_isoformat()
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="exposure_scan")

        issues = results.get('issues', [])
        has_critical = any(i.get('severity') in ('Critical', 'High') for i in issues)

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': has_critical,
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/malware")
async def check_malware(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_malware_analysis(url)

        findings = {
            'url': url,
            'sqli': [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'malware_analysis': results,
            'timestamp': utc_now_isoformat()
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="malware_scan")
        has_high_risk = any(str(i.get('severity') or '').title() in ('Critical', 'High') for i in (results.get('issues') or []))

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': has_high_risk,
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, user: Annotated['User', Depends(current_user)]):

    scan = ScanResult.query.filter_by(public_id=scan_id).first_or_404()
    if scan.user_id != user.id and not user.is_admin:
        raise HTTPException(403, 'Unauthorized')

    try:
        report_path = scan.report_path
        screenshot_paths = collect_screenshot_paths(scan.findings or {})
        linked_jobs = ScanJob.query.filter_by(result_id=scan.id).all()
        for job in linked_jobs:
            job.result_id = None

        db.session.delete(scan)
        db.session.commit()

        if report_path and os.path.exists(report_path):
            try:
                os.remove(report_path)
            except OSError:
                pass
        for path in screenshot_paths:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

        return {'status': 'success', 'message': 'Scan deleted'}
    except Exception as e:
        db.session.rollback()
        raise HTTPException(500, str(e))


@router.post("/scan/dns")
async def check_dns(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_dns(url)

        findings = {
            'url': url,
            'sqli': [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'dns': results,
            'timestamp': utc_now_isoformat(),
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="dns_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/redirect")
async def check_redirect(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_redirect(url)

        findings = {
            'url': url,
            'sqli': [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'redirect': results,
            'timestamp': utc_now_isoformat(),
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="redirect_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/takeover")
async def check_takeover(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_takeover(url)

        findings = {
            'url': url,
            'sqli': [],
            'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'takeover': results,
            'timestamp': utc_now_isoformat(),
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="takeover_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'subdomains_checked': results.get('subdomains_checked', []),
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/auth")
async def check_auth(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_auth(url)

        findings = {
            'url': url,
            'sqli': [], 'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'auth': results,
            'timestamp': utc_now_isoformat(),
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="auth_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/integrity")
async def check_integrity(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_integrity(url)

        findings = {
            'url': url,
            'sqli': [], 'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'integrity': results,
            'timestamp': utc_now_isoformat(),
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="integrity_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/logging_monitor")
async def check_logging_monitor(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        scanner = _security_scanner()
        results = scanner.check_logging_monitor(url)

        findings = {
            'url': url,
            'sqli': [], 'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'logging_monitor': results,
            'timestamp': utc_now_isoformat(),
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="logging_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan/ssrf")
async def check_ssrf(request: Request, user: Annotated['User', Depends(current_user)]):
    try:
        payload = ScanRequestPayload.model_validate(await request.json())
        url = normalize_target_url(payload.url)
        _preflight(user, url)

        if payload.enable_active_checks:
            _ensure_active_checks_authorized(user, url, payload.verified_target_id)

        scanner = _security_scanner()
        results = scanner.check_ssrf(url, enable_active_checks=payload.enable_active_checks)

        findings = {
            'url': url,
            'sqli': [], 'ssl': {'valid': True},
            'headers': {'status': 'not_run', 'issues': []},
            'wordpress': {'status': 'not_run', 'is_wordpress': False, 'issues': []},
            'zap': {'enabled': False, 'status': 'not_run', 'issues': []},
            'malicious': {'is_malicious': False},
            'ssrf': results,
            'timestamp': utc_now_isoformat(),
        }
        findings['summary'] = build_scan_summary(findings)
        findings['sections'] = build_scan_sections(findings)

        scan = persist_scan(user, findings, prefix="ssrf_scan")

        return {
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'params_tested': results.get('params_tested', []),
            'summary': findings['summary'],
        }

    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc))
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/health")
def health_check():
    return {'status': 'OK', 'message': 'Service is healthy'}
