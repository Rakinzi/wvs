from flask import Blueprint, jsonify, request, send_file
from app.scanners import SecurityScanner
from app.models import ScanResult, User
from app.utils.reports import generate_report
from app import db
from datetime import datetime
import os
# from flask_jwt_extended import jwt_required, get_jwt_identity

bp = Blueprint('scans', __name__)

@bp.route('/scan', methods=['POST'])
# @jwt_required()
def start_scan():
    try:
        # current_user = User.query.filter_by(username=get_jwt_identity()).first()
        # if not current_user:
        #     return jsonify({'error': 'User not found'}), 404
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        
        
        # Perform the scan synchronously
        scanner = SecurityScanner()
        
        results = {
            'url': url,
            'sqli': scanner.check_sql_injection(url),
            'ssl': scanner.check_ssl(url),
            'malicious': scanner.malicious_detector.analyze_url(url),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Generate report
        report_buffer = generate_report(results)
        filename = f"reports/scan_{datetime.utcnow().timestamp()}.pdf"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'wb') as f:
            f.write(report_buffer.getbuffer())
        
        # Save to database
        scan = ScanResult(
            url=results['url'],
            findings=results,
            report_path=filename
        )
        
        db.session.add(scan)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'scan_id': scan.id,
            'url': scan.url,
            'findings': results,
            'timestamp': scan.timestamp.isoformat()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/scan/sqli', methods=['POST'])
# @jwt_required()
def check_sql_injection():
    try:
        # current_user = User.query.filter_by(username=get_jwt_identity()).first()
        # if not current_user:
        #     return jsonify({'error': 'User not found'}), 404
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        
        
        # Perform the scan synchronously
        scanner = SecurityScanner()
        results = scanner.check_sql_injection(url)
        
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

@bp.route('/scan/ssl', methods=['POST'])
# @jwt_required()
def check_ssl():
    try:
        # current_user = User.query.filter_by(username=get_jwt_identity()).first()
        # print(current_user)
        # if not current_user:
        #     return jsonify({'error': 'User not found'}), 404
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        
        
        scanner = SecurityScanner()
        results = scanner.check_ssl(url)
        
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


@bp.route('/scan/malicious', methods=['POST'])
# @jwt_required()
def check_malicious():
    try:
        # current_user = User.query.filter_by(username=get_jwt_identity()).first()
        # if not current_user:
        #     return jsonify({'error': 'User not found'}),
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        
        
        scanner = SecurityScanner()
        results = scanner.malicious_detector.analyze_url(url)
        
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
# @jwt_required()
def get_report(scan_id):
    try:
        # current_user = User.query.filter_by(username=get_jwt_identity()).first()
        # if not current_user:
        #     return jsonify({'error': 'User not found'}), 404
        scan = ScanResult.query.get_or_404(scan_id)
        return send_file(scan.report_path, mimetype='application/pdf')
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