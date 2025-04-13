# wvs_backend/app/routes/dashboard.py

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import ScanResult, User, MaliciousSite, BlockedRequest
from app import db
from sqlalchemy import func, desc, and_, text
from datetime import datetime, timedelta
import json

bp = Blueprint('dashboard', __name__)

@bp.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Get overall stats
        total_scans = ScanResult.query.count()
        
        # For MySQL, we need to use JSON_EXTRACT and JSON_LENGTH instead of PostgreSQL-style operators
        # Count SQL injection vulnerabilities
        vulnerable_scans_sql = db.session.query(ScanResult).filter(
            text("JSON_LENGTH(JSON_EXTRACT(findings, '$.sqli')) > 0")
        ).count()
        
        # Count SSL issues
        vulnerable_scans_ssl = db.session.query(ScanResult).filter(
            text("JSON_EXTRACT(findings, '$.ssl.valid') = 'false' OR JSON_EXTRACT(findings, '$.ssl.valid') = false")
        ).count()
        
        # Count malicious content
        vulnerable_scans_malicious = db.session.query(ScanResult).filter(
            text("JSON_EXTRACT(findings, '$.malicious.is_malicious') = 'true' OR JSON_EXTRACT(findings, '$.malicious.is_malicious') = true")
        ).count()
        
        # Total unique vulnerable scans (some may have multiple vulnerabilities)
        vulnerable_scans_query = db.session.query(ScanResult).filter(
            text("JSON_LENGTH(JSON_EXTRACT(findings, '$.sqli')) > 0 OR " +
                 "JSON_EXTRACT(findings, '$.ssl.valid') = 'false' OR " +
                 "JSON_EXTRACT(findings, '$.ssl.valid') = false OR " +
                 "JSON_EXTRACT(findings, '$.malicious.is_malicious') = 'true' OR " +
                 "JSON_EXTRACT(findings, '$.malicious.is_malicious') = true")
        )
        vulnerable_scans = vulnerable_scans_query.count()
        
        # Get count of blocked sites
        blocked_sites = MaliciousSite.query.count()
        
        # Today's stats
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        today_scans = ScanResult.query.filter(
            ScanResult.timestamp >= today_start
        ).count()
        
        today_vulnerabilities = db.session.query(ScanResult).filter(
            and_(
                ScanResult.timestamp >= today_start,
                text("JSON_LENGTH(JSON_EXTRACT(findings, '$.sqli')) > 0 OR " +
                     "JSON_EXTRACT(findings, '$.ssl.valid') = 'false' OR " +
                     "JSON_EXTRACT(findings, '$.ssl.valid') = false OR " +
                     "JSON_EXTRACT(findings, '$.malicious.is_malicious') = 'true' OR " +
                     "JSON_EXTRACT(findings, '$.malicious.is_malicious') = true")
            )
        ).count()
        
        today_blocked_attempts = BlockedRequest.query.filter(
            BlockedRequest.timestamp >= today_start
        ).count()
        
        # Recent scans
        recent_scans = []
        recent_scan_results = ScanResult.query.order_by(
            ScanResult.timestamp.desc()
        ).limit(5).all()
        
        for scan in recent_scan_results:
            has_vulnerabilities = False
            findings = scan.findings
            
            # Check if scan has any vulnerabilities
            if findings.get('sqli') and findings['sqli']:
                has_vulnerabilities = True
            elif findings.get('ssl') and findings['ssl'].get('valid') is False:
                has_vulnerabilities = True
            elif findings.get('malicious') and findings['malicious'].get('is_malicious'):
                has_vulnerabilities = True
            
            recent_scans.append({
                'id': scan.id,
                'url': scan.url,
                'timestamp': scan.timestamp.isoformat(),
                'hasVulnerabilities': has_vulnerabilities
            })
        
        # Vulnerability types
        vulnerability_types = []
        
        # Add each type of vulnerability with its count
        if vulnerable_scans_sql > 0:
            vulnerability_types.append({
                'name': 'SQL Injection',
                'value': vulnerable_scans_sql
            })
        
        if vulnerable_scans_ssl > 0:
            vulnerability_types.append({
                'name': 'SSL Issues',
                'value': vulnerable_scans_ssl
            })
        
        if vulnerable_scans_malicious > 0:
            vulnerability_types.append({
                'name': 'Malicious Content',
                'value': vulnerable_scans_malicious
            })
        
        # Add default values if no vulnerabilities found
        if not vulnerability_types:
            vulnerability_types = [
                {'name': 'SQL Injection', 'value': 0},
                {'name': 'SSL Issues', 'value': 0},
                {'name': 'Malicious Content', 'value': 0}
            ]
        
        # Get scan activity by day (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        # Generate date list for the last 7 days
        date_list = []
        for i in range(7):
            day = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
            date_list.append(day)
        
        date_list.reverse()  # Oldest to newest
        
        # Initialize the scans by day with 0 counts
        scans_by_day = []
        for day in date_list:
            scans_by_day.append({
                'date': day,
                'scans': 0,
                'vulnerabilities': 0
            })
        
        # For MySQL, we need to use DATE() function
        # Query for scans by day
        scan_counts = db.session.query(
            func.date(ScanResult.timestamp).label('date'),
            func.count(ScanResult.id).label('count')
        ).filter(
            ScanResult.timestamp >= seven_days_ago
        ).group_by(
            func.date(ScanResult.timestamp)
        ).all()
        
        # Query for vulnerabilities by day
        vuln_counts = db.session.query(
            func.date(ScanResult.timestamp).label('date'),
            func.count(ScanResult.id).label('count')
        ).filter(
            and_(
                ScanResult.timestamp >= seven_days_ago,
                text("JSON_LENGTH(JSON_EXTRACT(findings, '$.sqli')) > 0 OR " +
                     "JSON_EXTRACT(findings, '$.ssl.valid') = 'false' OR " +
                     "JSON_EXTRACT(findings, '$.ssl.valid') = false OR " +
                     "JSON_EXTRACT(findings, '$.malicious.is_malicious') = 'true' OR " +
                     "JSON_EXTRACT(findings, '$.malicious.is_malicious') = true")
            )
        ).group_by(
            func.date(ScanResult.timestamp)
        ).all()
        
        # Update scan counts
        for date_str, count in scan_counts:
            date_str = date_str.strftime('%Y-%m-%d') if hasattr(date_str, 'strftime') else str(date_str)
            for day in scans_by_day:
                if day['date'] == date_str:
                    day['scans'] = count
                    break
        
        # Update vulnerability counts
        for date_str, count in vuln_counts:
            date_str = date_str.strftime('%Y-%m-%d') if hasattr(date_str, 'strftime') else str(date_str)
            for day in scans_by_day:
                if day['date'] == date_str:
                    day['vulnerabilities'] = count
                    break
        
        # Get blocked attempts by day
        blocked_attempts_by_day = []
        
        # Initialize with 0 counts
        for day in date_list:
            blocked_attempts_by_day.append({
                'date': day,
                'count': 0
            })
        
        # Query for blocked attempts by day
        blocked_counts = db.session.query(
            func.date(BlockedRequest.timestamp).label('date'),
            func.count(BlockedRequest.id).label('count')
        ).filter(
            BlockedRequest.timestamp >= seven_days_ago
        ).group_by(
            func.date(BlockedRequest.timestamp)
        ).all()
        
        # Update blocked attempt counts
        for date_str, count in blocked_counts:
            date_str = date_str.strftime('%Y-%m-%d') if hasattr(date_str, 'strftime') else str(date_str)
            for day in blocked_attempts_by_day:
                if day['date'] == date_str:
                    day['count'] = count
                    break
        
        # Get top malicious domains
        top_malicious_domains = []
        
        # Query for blocked request counts by domain using MySQL LIKE
        try:
            domain_counts = db.session.query(
                MaliciousSite.domain,
                func.count(BlockedRequest.id).label('count')
            ).join(
                BlockedRequest,
                BlockedRequest.url.like(func.concat('%', MaliciousSite.domain, '%'))
            ).group_by(
                MaliciousSite.domain
            ).order_by(
                func.count(BlockedRequest.id).desc()
            ).limit(5).all()
            
            # If no joined data, just get top 5 domains
            if not domain_counts:
                malicious_sites = MaliciousSite.query.order_by(
                    MaliciousSite.date_added.desc()
                ).limit(5).all()
                
                top_malicious_domains = [
                    {'domain': site.domain, 'count': 0}
                    for site in malicious_sites
                ]
            else:
                top_malicious_domains = [
                    {'domain': domain, 'count': count}
                    for domain, count in domain_counts
                ]
        except Exception as e:
            # Fallback if the query fails
            malicious_sites = MaliciousSite.query.order_by(
                MaliciousSite.date_added.desc()
            ).limit(5).all()
            
            top_malicious_domains = [
                {'domain': site.domain, 'count': 0}
                for site in malicious_sites
            ]
        
        # Assemble the stats response
        stats = {
            'totalScans': total_scans,
            'vulnerableScans': vulnerable_scans,
            'blockedSites': blocked_sites,
            'today': {
                'scans': today_scans,
                'vulnerabilities': today_vulnerabilities,
                'blockedAttempts': today_blocked_attempts
            },
            'recentScans': recent_scans,
            'vulnerabilityTypes': vulnerability_types,
            'scansByDay': scans_by_day,
            'blockedAttemptsByDay': blocked_attempts_by_day,
            'topMaliciousDomains': top_malicious_domains
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