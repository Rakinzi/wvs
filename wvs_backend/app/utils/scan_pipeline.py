from __future__ import annotations

import os

from app.scanners import SecurityScanner
from app.utils.db_manager import DBManager
from app.utils.launch_verdict import build_launch_verdict
from app.utils.reports import generate_report
from app.utils.scan_helpers import build_scan_sections, build_scan_summary
from app.utils.time_utils import utc_now, utc_now_isoformat


def ensure_reports_dir() -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def attach_launch_verdict(findings: dict) -> dict:
    verdict = build_launch_verdict(findings)
    findings['launch_verdict'] = {key: value for key, value in verdict.items() if key != 'universal_findings'}
    findings['universal_findings'] = verdict['universal_findings']
    if isinstance(findings.get('summary'), dict):
        findings['summary']['launch_verdict'] = findings['launch_verdict'].get('verdict')
        findings['summary']['launch_verdict_label'] = findings['launch_verdict'].get('label')
    return findings


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


def build_full_scan(url: str, progress_callback=None, enable_active_checks: bool = False) -> dict:
    scanner = SecurityScanner()
    findings = {
        'url': url,
        'timestamp': utc_now_isoformat(),
        'scan_profile': 'full_scan',
    }
    steps = [
        ('screenshots', 'site screenshots', scanner.capture_screenshots),
        ('sqli', 'SQL injection', lambda target: scanner.check_sql_injection(target, enable_active_checks=enable_active_checks)),
        ('ssl', 'SSL/TLS', scanner.check_ssl),
        ('headers', 'security headers', scanner.check_headers),
        ('wordpress', 'WordPress', lambda target: scanner.check_wordpress(target, enable_active_checks=enable_active_checks)),
        ('zap', 'OWASP ZAP', lambda target: scanner.check_zap(target, enable_active_checks=enable_active_checks)),
        ('nikto', 'Nikto web server scan', lambda target: scanner.check_nikto(target, enable_active_checks=enable_active_checks)),
        ('malicious', 'malicious reputation', scanner.malicious_detector.analyze_url),
        ('malware_analysis', 'malware analysis', scanner.check_malware_analysis),
        ('xss', 'XSS', scanner.check_xss),
        ('tech', 'technology stack', scanner.check_tech),
        ('exposure', 'exposed files', lambda target: scanner.check_exposure(target, enable_active_checks=enable_active_checks)),
        ('secrets', 'hardcoded secrets', scanner.check_secrets),
        ('dns', 'DNS', scanner.check_dns),
        ('redirect', 'open redirects', scanner.check_redirect),
        ('takeover', 'subdomain takeover', scanner.check_takeover),
        ('ssrf', 'SSRF', lambda target: scanner.check_ssrf(target, enable_active_checks=enable_active_checks)),
        ('logging_monitor', 'logging & monitoring', scanner.check_logging_monitor),
        ('auth', 'authentication controls', scanner.check_auth),
        ('integrity', 'software integrity', scanner.check_integrity),
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
    attach_launch_verdict(findings)
    return findings


def build_product_readiness_scan(
    url: str,
    *,
    page_paths: list[str] | None = None,
    enable_ai_review: bool = False,
    enable_active_checks: bool = False,
    active_check_paths: list[str] | None = None,
    active_check_budget: int | None = None,
    auth_test_accounts: list[dict] | None = None,
    protected_paths: list[str] | None = None,
    idor_paths: list[str] | None = None,
    page_type: str | None = None,
    progress_callback=None,
) -> dict:
    scanner = SecurityScanner()
    findings = {
        'url': url,
        'timestamp': utc_now_isoformat(),
        'scan_profile': 'product_readiness',
        'scan_config': {
            'page_paths': page_paths or [],
            'enable_ai_review': enable_ai_review,
            'enable_active_checks': enable_active_checks,
            'active_check_paths': active_check_paths or [],
            'active_check_budget': active_check_budget,
            'auth_test_accounts': auth_test_accounts or [],
            'protected_paths': protected_paths or [],
            'idor_paths': idor_paths or [],
            'page_type': page_type,
        },
    }
    steps = [
        ('accessibility', 'accessibility', lambda target: scanner.check_accessibility(target, page_paths=page_paths)),
        ('responsive_ux', 'responsive layout', lambda target: scanner.check_responsive_ux(target, page_paths=page_paths)),
        ('performance_ux', 'performance experience', lambda target: scanner.check_performance_ux(target, page_paths=page_paths)),
        ('form_usability', 'form usability', lambda target: scanner.check_form_usability(target, page_paths=page_paths)),
        ('seo', 'seo readiness', lambda target: scanner.check_seo(target, page_paths=page_paths, page_type=page_type)),
        ('broken_links', 'broken links', lambda target: scanner.check_broken_links(target, page_paths=page_paths)),
        ('app_controls', 'application controls', lambda target: scanner.check_app_controls(target, page_paths=page_paths, active_check_paths=active_check_paths, auth_test_accounts=auth_test_accounts, protected_paths=protected_paths, idor_paths=idor_paths)),
        ('exposed_services', 'exposed services', scanner.check_exposed_services),
        ('abuse_controls', 'abuse controls', lambda target: scanner.check_abuse_controls(target, endpoints=active_check_paths, budget=active_check_budget, enabled=enable_active_checks)),
        ('visual_ai', 'ai visual review', lambda target: scanner.check_visual_ai(target, page_paths=page_paths, enabled=enable_ai_review, page_type=page_type)),
    ]
    total_steps = len(steps)

    for step_index, (step_key, step_label, step_func) in enumerate(steps, start=1):
        _emit_progress(
            progress_callback,
            stage='running',
            step_key=step_key,
            step_label=step_label.title(),
            step_index=step_index,
            total_steps=total_steps,
            message=f'Checking {step_label}',
        )
        findings[step_key] = step_func(url)
        _emit_progress(
            progress_callback,
            stage='completed_step',
            step_key=step_key,
            step_label=step_label.title(),
            step_index=step_index,
            total_steps=total_steps,
            message=f'Completed {step_label}',
        )

    launch_blockers = []
    for section_key in ('accessibility', 'responsive_ux', 'performance_ux', 'form_usability', 'seo', 'broken_links', 'app_controls', 'exposed_services', 'abuse_controls'):
        for issue in (findings.get(section_key, {}) or {}).get('issues', []):
            if str(issue.get('severity') or '').lower() in {'critical', 'high'}:
                launch_blockers.append(issue)

    issue_total = sum(
        len((findings.get(key, {}) or {}).get('issues', []))
        for key in ('accessibility', 'responsive_ux', 'performance_ux', 'form_usability', 'seo', 'broken_links', 'app_controls', 'exposed_services', 'abuse_controls')
    )
    findings['launch_readiness'] = {
        'status': 'blocked' if launch_blockers else ('attention_required' if issue_total else 'ready'),
        'score': max(0, 100 - (len(launch_blockers) * 20) - max(0, issue_total - len(launch_blockers)) * 6),
        'blockers': launch_blockers[:10],
        'summary': 'Critical product-readiness issues detected before launch.' if launch_blockers else ('Some improvements are recommended before launch.' if issue_total else 'No measured product-readiness issues detected.'),
    }
    findings['summary'] = build_scan_summary(findings)
    findings['sections'] = build_scan_sections(findings)
    attach_launch_verdict(findings)
    return findings


def build_full_launch_audit(
    url: str,
    *,
    page_paths: list[str] | None = None,
    enable_ai_review: bool = False,
    enable_active_checks: bool = False,
    active_check_paths: list[str] | None = None,
    active_check_budget: int | None = None,
    auth_test_accounts: list[dict] | None = None,
    protected_paths: list[str] | None = None,
    idor_paths: list[str] | None = None,
    page_type: str | None = None,
    progress_callback=None,
) -> dict:
    findings = build_full_scan(url, progress_callback=progress_callback, enable_active_checks=enable_active_checks)
    ux_findings = build_product_readiness_scan(
        url,
        page_paths=page_paths,
        enable_ai_review=enable_ai_review,
        enable_active_checks=enable_active_checks,
        active_check_paths=active_check_paths,
        active_check_budget=active_check_budget,
        auth_test_accounts=auth_test_accounts,
        protected_paths=protected_paths,
        idor_paths=idor_paths,
        page_type=page_type,
        progress_callback=progress_callback,
    )
    for key in ('accessibility', 'responsive_ux', 'performance_ux', 'form_usability', 'seo', 'broken_links', 'app_controls', 'exposed_services', 'abuse_controls', 'visual_ai', 'launch_readiness', 'scan_config'):
        findings[key] = ux_findings.get(key)
    findings['scan_profile'] = 'full_launch_audit'
    findings['summary'] = build_scan_summary(findings)
    findings['sections'] = build_scan_sections(findings)
    attach_launch_verdict(findings)
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
    timestamp = utc_now().timestamp()
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
