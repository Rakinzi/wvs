from flask import Blueprint, jsonify, request, send_file
from app.scanners import SecurityScanner
from app.models import ScanResult, User
from app.utils.reports import generate_report
from app.utils.db_manager import DBManager
from app import db
from datetime import datetime
import os
from flask_jwt_extended import jwt_required, get_jwt_identity

bp = Blueprint('scans', __name__)

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
            # Add to malicious database for future checks
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
        report_buffer = generate_report(results)
        filename = f"reports/scan_{datetime.utcnow().timestamp()}.pdf"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'wb') as f:
            f.write(report_buffer.getbuffer())
        
        # Save to database
        scan_id = DBManager.save_scan_result(
            url=results['url'],
            findings=results,
            report_path=filename,
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
        
        return jsonify({
            'status': 'success',
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
        
        return jsonify({
            'status': 'success',
            'url': url,
            'findings': results,
            'recommendations': recommendations
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp.route('/scan/malicious', methods=['POST'])
@jwt_required()
def check_malicious():
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'Invalid URL protocol'}), 400
        
        # First check the database
        is_malicious, reason = DBManager.check_malicious_url(url)
        if is_malicious:
            return jsonify({
                'status': 'success',
                'url': url,
                'findings': {
                    'is_malicious': True,
                    'reason': reason,
                    'from_database': True
                }
            }), 200
        
        # Then use the scanner
        scanner = SecurityScanner()
        results = scanner.malicious_detector.analyze_url(url)
        
        # If malicious, add to database
        if results['is_malicious']:
            reason = []
            if results['phishing_match']:
                reason.append("Phishing site")
            if results['dnsbl'].get('blacklisted', False):
                reason.append("Listed in DNS blacklists")
            if results['score'] >= 7:
                reason.append("Suspicious URL characteristics")
                
            reason_str = " | ".join(reason) or "Malicious site"
            DBManager.add_malicious_url(url, reason_str, "api_scan")
        
        return jsonify({
            'status': 'success',
            'url': url,
            'findings': results
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
            
        return send_file(scan.report_path, mimetype='application/pdf')
    except Exception as e:
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
        
@bp.route('/scan/ai_scan', methods=['POST'])
@jwt_required()
def ai_scanner():
    try:
        current_user = User.query.filter_by(username=get_jwt_identity()).first()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        scanner = SecurityScanner()
        prediction_int, prediction_label = scanner.check_ai(url)
        
        # If it's a malicious site, add to database
        if prediction_label in ["phishing", "malware", "defacement"]:
            DBManager.add_malicious_url(url, f"AI classified as {prediction_label}", "ai_scan")
        
        return jsonify({
            'status': 'success',
            'url': url,
            'prediction': str(prediction_int),
            'label': prediction_label,
            'is_malicious': prediction_label in ["phishing", "malware", "defacement"]
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500