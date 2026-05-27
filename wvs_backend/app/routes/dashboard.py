from collections import Counter
from datetime import timedelta
from urllib.parse import urlparse

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

from app.auth import get_current_user
from app.models import BlockedRequest, MaliciousSite, ScanResult, UptimeMonitor
from app.services.uptime import calculate_uptime_percent
from app.utils.scan_helpers import build_scan_summary
from app.utils.time_utils import utc_now


bp = Blueprint('dashboard', __name__)


@bp.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(
            ScanResult.timestamp.desc()
        ).all()
        monitors = UptimeMonitor.query.filter_by(user_id=current_user.id).order_by(
            UptimeMonitor.created_at.desc()
        ).all()
        can_view_security_feed = current_user.is_admin
        blocked_requests = []
        malicious_sites = []
        if can_view_security_feed:
            blocked_requests = BlockedRequest.query.order_by(BlockedRequest.timestamp.desc()).all()
            malicious_sites = MaliciousSite.query.order_by(MaliciousSite.date_added.desc()).all()

        today_start = utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
        seven_days_ago = utc_now() - timedelta(days=7)

        vulnerable_scans_sql = 0
        vulnerable_scans_ssl = 0
        vulnerable_scans_malicious = 0
        vulnerable_scans_headers = 0
        vulnerable_scans_wordpress = 0
        vulnerable_scans_zap = 0
        vulnerable_scans_xss = 0
        vulnerable_scans_exposure = 0
        vulnerable_scans_dependencies = 0
        vulnerable_scans_malware_artifacts = 0
        vulnerable_scans = 0
        today_scans = 0
        today_vulnerabilities = 0
        total_dependency_advisories = 0
        recent_scans = []
        scans_by_day_map = {}
        vulnerabilities_by_day_map = {}

        for scan in scans:
            findings = scan.findings or {}
            summary = findings.get('summary') or build_scan_summary(findings)
            scan_day = scan.timestamp.strftime('%Y-%m-%d')
            scans_by_day_map[scan_day] = scans_by_day_map.get(scan_day, 0) + 1

            if scan.timestamp >= today_start:
                today_scans += 1
            if scan.timestamp >= seven_days_ago and summary['vulnerable']:
                vulnerabilities_by_day_map[scan_day] = vulnerabilities_by_day_map.get(scan_day, 0) + 1

            if summary['sqli_count'] > 0:
                vulnerable_scans_sql += 1
            if summary['ssl_issue']:
                vulnerable_scans_ssl += 1
            if summary['malicious']:
                vulnerable_scans_malicious += 1
            if summary['header_issue_count'] > 0:
                vulnerable_scans_headers += 1
            if summary.get('wordpress_issue_count', 0) > 0:
                vulnerable_scans_wordpress += 1
            if summary.get('zap_issue_count', 0) > 0:
                vulnerable_scans_zap += 1
            if summary.get('xss_count', 0) > 0:
                vulnerable_scans_xss += 1
            if summary.get('exposure_count', 0) > 0:
                vulnerable_scans_exposure += 1
            if summary.get('malware_artifact_count', 0) > 0:
                vulnerable_scans_malware_artifacts += 1
            if summary.get('advisory_count', 0) > 0:
                vulnerable_scans_dependencies += 1
                total_dependency_advisories += summary.get('advisory_count', 0)
            if summary['vulnerable']:
                vulnerable_scans += 1
                if scan.timestamp >= today_start:
                    today_vulnerabilities += 1

            if len(recent_scans) < 5:
                recent_scans.append({
                    'id': scan.public_id,
                    'url': scan.url,
                    'timestamp': scan.timestamp.isoformat(),
                    'hasVulnerabilities': summary['vulnerable']
                })

        vulnerability_types = [
            {'name': 'SQL Injection',    'value': vulnerable_scans_sql},
            {'name': 'SSL Issues',       'value': vulnerable_scans_ssl},
            {'name': 'Malicious Content','value': vulnerable_scans_malicious},
            {'name': 'Header Issues',    'value': vulnerable_scans_headers},
            {'name': 'WordPress Issues', 'value': vulnerable_scans_wordpress},
            {'name': 'ZAP Alerts',       'value': vulnerable_scans_zap},
            {'name': 'XSS',              'value': vulnerable_scans_xss},
            {'name': 'Dependency CVEs',  'value': vulnerable_scans_dependencies},
            {'name': 'File Exposure',    'value': vulnerable_scans_exposure},
            {'name': 'Malware Artifacts','value': vulnerable_scans_malware_artifacts},
        ]

        date_list = [
            (utc_now() - timedelta(days=offset)).strftime('%Y-%m-%d')
            for offset in range(6, -1, -1)
        ]
        scans_by_day = [
            {
                'date': day,
                'scans': scans_by_day_map.get(day, 0),
                'vulnerabilities': vulnerabilities_by_day_map.get(day, 0),
            }
            for day in date_list
        ]

        blocked_attempts_by_day_map = {}
        today_blocked_attempts = 0
        blocked_domain_counter = Counter()

        for blocked in blocked_requests:
            day = blocked.timestamp.strftime('%Y-%m-%d')
            if blocked.timestamp >= seven_days_ago:
                blocked_attempts_by_day_map[day] = blocked_attempts_by_day_map.get(day, 0) + 1
            if blocked.timestamp >= today_start:
                today_blocked_attempts += 1
            domain = urlparse(blocked.url).netloc
            if domain:
                blocked_domain_counter[domain] += 1

        blocked_attempts_by_day = [
            {'date': day, 'count': blocked_attempts_by_day_map.get(day, 0)}
            for day in date_list
        ]

        monitors_up = sum(1 for monitor in monitors if monitor.status == 'up')
        monitors_down = sum(1 for monitor in monitors if monitor.status == 'down')
        uptime_values = [value for value in (calculate_uptime_percent(monitor, hours=24) for monitor in monitors) if value is not None]
        average_uptime_percent = round(sum(uptime_values) / len(uptime_values), 1) if uptime_values else None

        recent_monitors = [
            {
                'id': monitor.public_id,
                'name': monitor.name,
                'target_url': monitor.target_url,
                'status': monitor.status,
                'last_checked_at': monitor.last_checked_at.isoformat() if monitor.last_checked_at else None,
                'last_response_time_ms': monitor.last_response_time_ms,
                'uptime_percent_24h': calculate_uptime_percent(monitor, hours=24),
            }
            for monitor in monitors[:5]
        ]

        top_malicious_domains = [
            {'domain': domain, 'count': count}
            for domain, count in blocked_domain_counter.most_common(5)
        ]
        if not top_malicious_domains:
            top_malicious_domains = [
                {'domain': site.domain, 'count': 0}
                for site in malicious_sites[:5]
            ]

        recent_blocked_attempts = [
            {
                'id': b.id,
                'url': b.url,
                'ip_address': b.ip_address,
                'timestamp': b.timestamp.isoformat() if b.timestamp else None,
                'reason': b.reason,
            }
            for b in blocked_requests[:5]
        ]

        stats = {
            'totalScans': len(scans),
            'vulnerableScans': vulnerable_scans,
            'blockedSites': len(malicious_sites),
            'uptimeMonitors': len(monitors),
            'uptimeUp': monitors_up,
            'uptimeDown': monitors_down,
            'averageUptimePercent': average_uptime_percent,
            'dependencyAdvisories': total_dependency_advisories,
            'today': {
                'scans': today_scans,
                'vulnerabilities': today_vulnerabilities,
                'blockedAttempts': today_blocked_attempts
            },
            'canViewSecurityFeed': can_view_security_feed,
            'recentScans': recent_scans,
            'vulnerabilityTypes': vulnerability_types,
            'scansByDay': scans_by_day,
            'blockedAttemptsByDay': blocked_attempts_by_day,
            'topMaliciousDomains': top_malicious_domains,
            'recentMonitors': recent_monitors,
            'recentBlockedAttempts': recent_blocked_attempts,
        }

        return jsonify({
            'status': 'success',
            'stats': stats
        }), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
