import os
import copy

from flask import Blueprint, current_app, jsonify, request, send_file
from flask_jwt_extended import jwt_required
from celery.exceptions import TimeoutError as CeleryTimeoutError
from app.auth import get_current_user
from app.scanners import SecurityScanner
from app.models import ScanJob, ScanResult, VerifiedTarget
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
from app.utils.scan_pipeline import persist_scan_result
from app.utils.reports import generate_report
from app.utils.ux_screenshot_manager import collect_screenshot_paths
from app.tasks.scan_jobs import run_full_scan_job
from app import celery, db, limiter
from pydantic import ValidationError
from app.utils.time_utils import utc_now, utc_now_isoformat

bp = Blueprint('scans', __name__)


def persist_scan(current_user, findings, prefix="scan"):
    return persist_scan_result(findings["url"], findings, current_user.id, prefix=prefix)


def _ensure_verified_target(current_user, url: str, verified_target_id: str | None):
    if not current_app.config.get("REQUIRE_VERIFIED_TARGETS", False):
        return None

    normalized = normalize_target_url(url)
    hostname = normalized.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    query = VerifiedTarget.query.filter_by(user_id=current_user.id, verification_status="verified")
    if verified_target_id:
        query = query.filter_by(public_id=verified_target_id)

    for candidate in query.all():
        if candidate.normalized_domain.lower() == hostname:
            return candidate

    raise ValueError("A verified target is required for this scan profile")


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
    task_result = celery.AsyncResult(task_id)

    try:
        state = task_result.state
        info = task_result.info if isinstance(task_result.info, dict) else {}
    except Exception:
        return None, {}

    return state, info


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
        return stored_progress

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
        return stored_progress

    return {
        'task_state': task_state,
        'current_step': info.get('current_step'),
        'current_step_label': info.get('current_step_label'),
        'step_index': info.get('step_index'),
        'total_steps': info.get('total_steps'),
        'percent': info.get('percent'),
        'message': info.get('message'),
        'logs': logs,
    }


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

    task_result = celery.AsyncResult(job.task_id)
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
    except CeleryTimeoutError:
        return job
    except Exception:
        job.status = "failed"
        job.completed_at = utc_now()
        if not job.error_message:
            job.error_message = _resolve_job_failure_message(task_result)
        _safe_commit()

    return job


def _asset_url(scan_id: str, filename: str) -> str:
    return f"/report/{scan_id}/assets/{filename}"


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

@bp.route('/scan', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
def start_scan():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)
        scan_profile = payload.scan_profile or 'security_only'

        if scan_profile in {'product_readiness', 'full_launch_audit'}:
            _ensure_verified_target(current_user, url, payload.verified_target_id)
        
        # Check if URL is known to be malicious first
        is_malicious, reason = DBManager.check_malicious_url(url)
        if is_malicious:
            return jsonify({
                'status': 'error',
                'message': f'URL is flagged as malicious: {reason}',
                'is_malicious': True
            }), 400
        
        job = ScanJob(
            url=url,
            scan_type=scan_profile,
            status='queued',
            user_id=current_user.id,
            findings={
                '_config': {
                    'page_paths': payload.page_paths,
                    'page_type': payload.page_type,
                    'enable_ai_review': payload.enable_ai_review,
                    'verified_target_id': payload.verified_target_id,
                }
            },
        )
        db.session.add(job)
        db.session.commit()

        try:
            queue_name = current_app.config["UX_SCAN_QUEUE"] if scan_profile in {"product_readiness", "full_launch_audit"} else current_app.config["SECURITY_SCAN_QUEUE"]
            task = run_full_scan_job.apply_async(args=[job.id], queue=queue_name)
            job.task_id = task.id
            db.session.commit()
        except Exception as exc:
            job.status = 'failed'
            job.error_message = f'Failed to queue scan job: {exc}'
            job.completed_at = utc_now()
            db.session.commit()
            return jsonify({
                'status': 'error',
                'message': 'Failed to queue scan job. Check Celery broker connectivity.',
            }), 503

        return jsonify({
            'status': 'accepted',
            'job_id': job.public_id,
            'task_id': task.id,
            'url': url,
            'scan_profile': scan_profile,
            'message': 'Scan queued successfully',
            'timestamp': job.created_at.isoformat()
        }), 202
        
    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/scan/sqli', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_sql_injection():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)
        
        # Perform the scan synchronously
        scanner = SecurityScanner()
        results = scanner.check_sql_injection(url)
        
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
        
        scan = persist_scan(current_user, findings, prefix="sqli_scan")
        
        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'vulnerable': findings['summary']['vulnerable'],
            'summary': findings['summary'],
        }), 200
        
    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/scan/ssl', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_ssl():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)
        
        scanner = SecurityScanner()
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
        
        scan = persist_scan(current_user, findings, prefix="ssl_scan")
        
        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'header_findings': findings['headers'],
            'wordpress_findings': findings['wordpress'],
            'summary': findings['summary'],
        }), 200
        
    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp.route('/scan/wordpress', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_wordpress():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)

        scanner = SecurityScanner()
        results = scanner.check_wordpress(url)
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

        scan = persist_scan(current_user, findings, prefix="wordpress_scan")

        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'summary': findings['summary'],
        }), 200

    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp.route('/scan/jobs/<string:job_id>', methods=['GET'])
@jwt_required()
def get_scan_job(job_id):
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    job = ScanJob.query.filter_by(public_id=job_id).first_or_404()
    if job.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    job = _sync_scan_job_status(job)

    payload = job.to_dict()
    payload['scan_id'] = job.result.public_id if job.result else None
    payload['has_vulnerabilities'] = bool(
        (job.findings or {}).get('summary', {}).get('vulnerable', False)
    )
    payload['progress'] = _serialize_task_progress(job)
    return jsonify({
        'status': 'success',
        'job': payload,
    }), 200


@bp.route('/scan/jobs', methods=['GET'])
@jwt_required()
def list_scan_jobs():
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    limit = request.args.get('limit', 20, type=int)
    jobs = ScanJob.query.filter_by(user_id=current_user.id).order_by(
        ScanJob.created_at.desc()
    ).limit(limit).all()
    jobs = [_sync_scan_job_status(job) for job in jobs]

    return jsonify({
        'status': 'success',
        'jobs': [
            {
                **job.to_dict(),
                'progress': _serialize_task_progress(job),
            }
            for job in jobs
        ],
    }), 200

@bp.route('/report/<string:scan_id>', methods=['GET'])
@jwt_required()
def get_report(scan_id):
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        scan = ScanResult.query.filter_by(public_id=scan_id).first_or_404()
        
        # Check if user owns the scan or is admin
        if scan.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Unauthorized access to report'}), 403
        
        report_format = request.args.get('format', 'pdf').lower()
        findings = scan.findings or {}
        if 'summary' not in findings:
            findings['summary'] = build_scan_summary(findings)
        if 'sections' not in findings:
            findings['sections'] = build_scan_sections(findings)

        if report_format == 'json':
            public_findings = _publicize_scan_assets(scan.public_id, copy.deepcopy(findings))
            public_findings['summary'] = build_scan_summary(public_findings)
            public_findings['sections'] = build_scan_sections(public_findings)
            summary = public_findings.get('summary', {})
            comparison = None
            previous_scan = _find_previous_scan_for_comparison(scan)
            if previous_scan is not None:
                previous_findings = previous_scan.findings or {}
                comparison = build_scan_comparison(public_findings, _publicize_scan_assets(previous_scan.public_id, copy.deepcopy(previous_findings)))
                comparison["previous_scan_id"] = previous_scan.public_id
                comparison["previous_timestamp"] = previous_scan.timestamp.isoformat()
            return jsonify({
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
            }), 200

        if report_format == 'sbom':
            return jsonify({
                'status': 'success',
                'sbom': {
                    'scan_id': scan.public_id,
                    'url': scan.url,
                    'timestamp': scan.timestamp.isoformat(),
                    'packages': (findings.get('tech') or {}).get('packages', []),
                    'advisories': (findings.get('tech') or {}).get('advisories', []),
                    'best_practices': build_best_practices(findings),
                },
            }), 200

        try:
            tz_offset = int(request.args.get('tz_offset', 0))
        except ValueError:
            tz_offset = 0

        # Serve cached PDF when one exists and tz_offset matches (avoids rebuilding on every download)
        cached_path = scan.report_path
        if cached_path and os.path.exists(cached_path) and tz_offset == 0:
            return send_file(
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
        if cached_path:
            try:
                os.makedirs(os.path.dirname(cached_path), exist_ok=True)
                with open(cached_path, 'wb') as f:
                    f.write(pdf_buffer.getbuffer())
                pdf_buffer.seek(0)
            except OSError:
                pdf_buffer.seek(0)

        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'scan_{scan.id}_report.pdf',
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp.route('/report/<string:scan_id>/assets/<path:asset_name>', methods=['GET'])
@jwt_required()
def get_report_asset(scan_id: str, asset_name: str):
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    scan = ScanResult.query.filter_by(public_id=scan_id).first_or_404()
    if scan.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized access to report assets'}), 403

    screenshot_paths = collect_screenshot_paths(scan.findings or {})
    allowed = {os.path.basename(path): path for path in screenshot_paths}
    target_path = allowed.get(asset_name)
    if not target_path or not os.path.exists(target_path):
        return jsonify({'error': 'Asset not found'}), 404

    return send_file(target_path, mimetype='image/png')

@bp.route('/scans/history', methods=['GET'])
@jwt_required()
def get_scan_history():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
            
        limit = request.args.get('limit', 20, type=int)
        scans = DBManager.get_user_scans(current_user.id, limit)
        
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
        
        return jsonify({
            'status': 'success',
            'scans': results
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/scan/xss', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_xss():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)

        scanner = SecurityScanner()
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

        scan = persist_scan(current_user, findings, prefix="xss_scan")

        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'vulnerable': results.get('reflected_xss_count', 0) > 0,
            'summary': findings['summary'],
        }), 200

    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scan/tech', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_tech():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)

        scanner = SecurityScanner()
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

        scan = persist_scan(current_user, findings, prefix="tech_scan")

        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'technologies': results.get('technologies', {}),
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'summary': findings['summary'],
        }), 200

    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scan/exposure', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_exposure():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)

        scanner = SecurityScanner()
        results = scanner.check_exposure(url)

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

        scan = persist_scan(current_user, findings, prefix="exposure_scan")

        issues = results.get('issues', [])
        has_critical = any(i.get('severity') in ('Critical', 'High') for i in issues)

        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': has_critical,
            'summary': findings['summary'],
        }), 200

    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scan/malware', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
def check_malware():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)

        scanner = SecurityScanner()
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

        scan = persist_scan(current_user, findings, prefix="malware_scan")
        has_high_risk = any(str(i.get('severity') or '').title() in ('Critical', 'High') for i in (results.get('issues') or []))

        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': has_high_risk,
            'summary': findings['summary'],
        }), 200

    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scans/<string:scan_id>', methods=['DELETE'])
@jwt_required()
def delete_scan(scan_id):
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    scan = ScanResult.query.filter_by(public_id=scan_id).first_or_404()
    if scan.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

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

        return jsonify({'status': 'success', 'message': 'Scan deleted'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scan/dns', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_dns():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)

        scanner = SecurityScanner()
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

        scan = persist_scan(current_user, findings, prefix="dns_scan")

        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'summary': findings['summary'],
        }), 200

    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scan/redirect', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_redirect():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)

        scanner = SecurityScanner()
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

        scan = persist_scan(current_user, findings, prefix="redirect_scan")

        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'summary': findings['summary'],
        }), 200

    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/scan/takeover', methods=['POST'])
@jwt_required()
@limiter.limit("20 per hour")
def check_takeover():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        payload = ScanRequestPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)

        scanner = SecurityScanner()
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

        scan = persist_scan(current_user, findings, prefix="takeover_scan")

        return jsonify({
            'status': 'success',
            'scan_id': scan.public_id,
            'url': url,
            'findings': results,
            'recommendations': results.get('recommendations', []),
            'vulnerable': bool(results.get('issues')),
            'subdomains_checked': results.get('subdomains_checked', []),
            'summary': findings['summary'],
        }), 200

    except (ValueError, ValidationError) as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/health', methods=['GET'])
def health_check():
    try:
        # Simple database check
        db.session.query(ScanResult).first()
        return jsonify({
            'status': 'OK', 
            'message': 'Service is healthy'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'ERROR',
            'message': str(e)
        }), 503
