from __future__ import annotations

import os
from datetime import datetime

from app.scanners import SecurityScanner
from app.utils.db_manager import DBManager
from app.utils.reports import generate_report
from app.utils.scan_helpers import build_scan_sections, build_scan_summary


def ensure_reports_dir() -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def _emit_progress(
    progress_callback,
    *,
    stage: str,
    step_key: str,
    step_label: str,
    step_index: int,
    total_steps: int,
    message: str,
) -> None:
    if progress_callback is None:
        return

    progress_callback(
        {
            'stage': stage,
            'step_key': step_key,
            'step_label': step_label,
            'step_index': step_index,
            'total_steps': total_steps,
            'percent': int((step_index / total_steps) * 100),
            'message': message,
        }
    )


def build_full_scan(url: str, progress_callback=None) -> dict:
    scanner = SecurityScanner()
    findings = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat()
    }
    steps = [
        ('sqli', 'SQL injection', scanner.check_sql_injection),
        ('ssl', 'SSL/TLS', scanner.check_ssl),
        ('headers', 'security headers', scanner.check_headers),
        ('wordpress', 'WordPress', scanner.check_wordpress),
        ('zap', 'OWASP ZAP', scanner.check_zap),
        ('malicious', 'malicious reputation', scanner.malicious_detector.analyze_url),
        ('xss', 'XSS', scanner.check_xss),
        ('tech', 'technology stack', scanner.check_tech),
        ('exposure', 'exposed files', scanner.check_exposure),
        ('dns', 'DNS', scanner.check_dns),
        ('redirect', 'open redirects', scanner.check_redirect),
        ('takeover', 'subdomain takeover', scanner.check_takeover),
    ]
    total_steps = len(steps)

    for step_index, (step_key, step_label, step_func) in enumerate(steps, start=1):
        _emit_progress(
            progress_callback,
            stage='running',
            step_key=step_key,
            step_label=step_label,
            step_index=step_index,
            total_steps=total_steps,
            message=f'Checking {step_label.lower()}',
        )
        findings[step_key] = step_func(url)
        _emit_progress(
            progress_callback,
            stage='completed_step',
            step_key=step_key,
            step_label=step_label,
            step_index=step_index,
            total_steps=total_steps,
            message=f'Completed {step_label.lower()}',
        )

    findings['summary'] = build_scan_summary(findings)
    findings['sections'] = build_scan_sections(findings)
    return findings


def tag_malicious_result(url: str, findings: dict) -> None:
    malicious = findings.get('malicious', {})
    dnsbl = malicious.get('dnsbl', {}) or {}
    high_confidence = (
        malicious.get('phishing_match') or
        dnsbl.get('domain_blacklisted', False) or
        malicious.get('score', 0) >= 7
    )
    if not (malicious.get('is_malicious') and high_confidence):
        return

    reasons = []
    if malicious.get('phishing_match'):
        reasons.append("Phishing site")
    if dnsbl.get('domain_blacklisted', False):
        reasons.append("Listed in domain blacklists")
    if malicious.get('score', 0) >= 7:
        reasons.append("Suspicious URL characteristics")

    DBManager.add_malicious_url(url, " | ".join(reasons) or "Malicious site", "scan")


def persist_scan_result(url: str, findings: dict, user_id: int, prefix: str = "scan") -> int:
    reports_dir = ensure_reports_dir()
    timestamp = datetime.utcnow().timestamp()
    report_filename = f"{prefix}_{timestamp}.pdf"
    report_path = os.path.join(reports_dir, report_filename)
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    report_buffer = generate_report(findings)
    with open(report_path, 'wb') as report_file:
        report_file.write(report_buffer.getbuffer())

    return DBManager.save_scan_result(
        url=url,
        findings=findings,
        report_path=os.path.abspath(report_path),
        user_id=user_id,
    )
