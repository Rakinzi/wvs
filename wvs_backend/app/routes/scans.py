from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.scanners import SecurityScanner
from app.models import ScanResult, User, BlockedRequest
from app.utils.reports import generate_report
from app.utils.db_manager import DBManager
from app import db
from datetime import datetime
import os
from urllib.parse import urlparse
import time

bp = Blueprint('scans', __name__)

def ensure_reports_dir():
    """Ensure that the reports directory exists and return its path"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, 'reports')
    
    # Create if it doesn't exist
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    return reports_dir

@bp.route('/scan', methods=['POST'])
@jwt_required()
def start_scan():
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'Invalid URL protocol'}), 400
        
        # Check if URL is known to be malicious first
        is_malicious, reason = DBManager.check_malicious_url(url)
        if is_malicious:
            return jsonify({
                'status': 'error',
                'message': f'URL is flagged as malicious: {reason}',
                'is_malicious': True
            }), 400
        
        # Perform the scan synchronously
        scanner = SecurityScanner()
        
        results = {
            'url': url,
            'sqli': scanner.check_sql_injection(url),
            'ssl': scanner.check_ssl(url),
            'malicious': scanner.malicious_detector.analyze_url(url),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Check if the site is malicious based on scan results
        if results['malicious']['is_malicious']:
            # Add to database for future checks
            reason = []
            if results['malicious']['phishing_match']:
                reason.append("Phishing site")
            if results['malicious']['dnsbl'].get('blacklisted', False):
                reason.append("Listed in DNS blacklists")
            if results['malicious']['score'] >= 7:
                reason.append("Suspicious URL characteristics")
                
            reason_str = " | ".join(reason) or "Malicious site"
            DBManager.add_malicious_url(url, reason_str, "scan")
        
        # Generate report
        reports_dir = ensure_reports_dir()
        timestamp = datetime.utcnow().timestamp()
        report_filename = f"scan_{timestamp}.pdf"
        report_path = os.path.join(reports_dir, report_filename)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        report_buffer = generate_report(results)
        with open(report_path, 'wb') as f:
            f.write(report_buffer.getbuffer())
        
        # Save to database with absolute path
        scan_id = DBManager.save_scan_result(
            url=results['url'],
            findings=results,
            report_path=os.path.abspath(report_path),
            user_id=current_user.id
        )
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'url': url,
            'findings': results,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/scan/sqli', methods=['POST'])
@jwt_required()
def check_sql_injection():
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'Invalid URL protocol'}), 400
        
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
            'sqli': results,
            'ssl': {'valid': True},  # Placeholder
            'malicious': {'is_malicious': False},  # Placeholder
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Save to database
        reports_dir = ensure_reports_dir()
        timestamp = datetime.utcnow().timestamp()
        report_filename = f"sqli_scan_{timestamp}.pdf"
        report_path = os.path.join(reports_dir, report_filename)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        # Generate a basic report for SQL injection only
        report_buffer = generate_report(findings)
        with open(report_path, 'wb') as f:
            f.write(report_buffer.getbuffer())
        
        scan_id = DBManager.save_scan_result(
            url=url,
            findings=findings,
            report_path=os.path.abspath(report_path),
            user_id=current_user.id
        )
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations,
            'vulnerable': len(results) > 0
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/scan/ssl', methods=['POST'])
@jwt_required()
def check_ssl():
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'Invalid URL protocol'}), 400
        
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
            'sqli': [],  # Placeholder
            'ssl': results,
            'malicious': {'is_malicious': False},  # Placeholder
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Save to database
        reports_dir = ensure_reports_dir()
        timestamp = datetime.utcnow().timestamp()
        report_filename = f"ssl_scan_{timestamp}.pdf"
        report_path = os.path.join(reports_dir, report_filename)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        # Generate a basic report for SSL only
        report_buffer = generate_report(findings)
        with open(report_path, 'wb') as f:
            f.write(report_buffer.getbuffer())
        
        scan_id = DBManager.save_scan_result(
            url=url,
            findings=findings,
            report_path=os.path.abspath(report_path),
            user_id=current_user.id
        )
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'url': url,
            'findings': results,
            'recommendations': recommendations
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/report/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_report(scan_id):
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        scan = ScanResult.query.get_or_404(scan_id)
        
        # Check if user owns the scan or is admin
        if scan.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Unauthorized access to report'}), 403
        
        # Get the report file path from the database
        report_path = scan.report_path
        
        # Check if the path exists
        if not os.path.exists(report_path):
            # Try with a different path - look in the app/reports directory
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            report_filename = os.path.basename(report_path)
            alternative_paths = [
                os.path.join(base_dir, 'reports', report_filename),
                os.path.join(os.getcwd(), 'reports', report_filename),
                os.path.join(os.getcwd(), 'app', 'reports', report_filename),
                os.path.join(os.getcwd(), 'wvs_backend', 'reports', report_filename),
                os.path.join(os.getcwd(), 'wvs_backend', 'app', 'reports', report_filename),
            ]
            
            # Try each alternative path
            for alt_path in alternative_paths:
                if os.path.exists(alt_path):
                    report_path = alt_path
                    print(f"Found report at alternate path: {alt_path}")
                    break
            else:
                # If no alternative path works, return an error with debugging info
                return jsonify({
                    'status': 'error',
                    'message': f'Report file not found. Original path: {scan.report_path}, tried alternatives. Base directory: {base_dir}, current working directory: {os.getcwd()}'
                }), 404
        
        # Return the file
        return send_file(report_path, mimetype='application/pdf')
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/scans/history', methods=['GET'])
@jwt_required()
def get_scan_history():
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
            
        limit = request.args.get('limit', 20, type=int)
        scans = DBManager.get_user_scans(current_user.id, limit)
        
        results = []
        for scan in scans:
            results.append({
                'id': scan.id,
                'url': scan.url,
                'timestamp': scan.timestamp.isoformat(),
                'has_vulnerabilities': (
                    len(scan.findings.get('sqli', [])) > 0 or
                    not scan.findings.get('ssl', {}).get('valid', True) or
                    scan.findings.get('malicious', {}).get('is_malicious', False)
                )
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