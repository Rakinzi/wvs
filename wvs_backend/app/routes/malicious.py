from flask import Blueprint, jsonify, request
from app.models import MaliciousSite, BlockedRequest
from app.utils.db_manager import DBManager
from app.scanners import SecurityScanner
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from datetime import datetime
import time

bp = Blueprint('malicious', __name__)

@bp.route('/api/malicious/check', methods=['GET'])
def check_malicious():
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    # Check database first (fastest)
    is_blocked, reason = DBManager.check_malicious_url(url)
    
    if is_blocked:
        return jsonify({
            'url': url,
            'blocked': True,
            'reason': reason or 'Domain in database'
        }), 200
    
    # If not in database, use the malicious detector
    scanner = SecurityScanner()
    malicious_result = scanner.malicious_detector.analyze_url(url)
    
    if malicious_result['is_malicious']:
        reason = []
        if malicious_result['phishing_match']:
            reason.append("Phishing site")
        if malicious_result['dnsbl'].get('blacklisted', False):
            reason.append("Listed in DNS blacklists")
        if malicious_result['score'] >= 7:
            reason.append("Suspicious URL characteristics")
            
        reason_str = " | ".join(reason) or "Malicious site"
        
        # Add to database for faster future lookups
        DBManager.add_malicious_url(url, reason_str, "scanner")
        
        return jsonify({
            'url': url,
            'blocked': True,
            'reason': reason_str,
            'details': malicious_result
        }), 200
    
    # Run AI prediction as a final check
    try:
        prediction_int, prediction_label = scanner.check_ai(url)
        if prediction_label in ["phishing", "malware", "defacement"]:
            reason_str = f"AI classified as {prediction_label}"
            DBManager.add_malicious_url(url, reason_str, "ai")
            return jsonify({
                'url': url,
                'blocked': True,
                'reason': reason_str
            }), 200
    except Exception:
        pass
        
    return jsonify({
        'url': url,
        'blocked': False
    }), 200

@bp.route('/api/malicious/list', methods=['GET'])
def list_malicious():
    since = request.args.get('since', 0, type=int)
    limit = request.args.get('limit', 1000, type=int)
    
    if since > 0:
        since_date = datetime.fromtimestamp(since)
        sites = MaliciousSite.query.filter(
            MaliciousSite.date_added > since_date
        ).limit(limit).all()
    else:
        sites = MaliciousSite.query.limit(limit).all()
    
    domains = [site.domain for site in sites]
    
    return jsonify({
        'count': len(domains),
        'domains': domains
    }), 200

@bp.route('/api/malicious/add', methods=['POST'])
@jwt_required()
def add_malicious():
    url = request.json.get('url')
    reason = request.json.get('reason', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    success = DBManager.add_malicious_url(url, reason, "manual")
    
    if success:
        return jsonify({'status': 'success', 'message': 'URL added to malicious database'}), 201
    else:
        return jsonify({'status': 'warning', 'message': 'URL already exists in database'}), 200
        
@bp.route('/api/blocked/log', methods=['POST'])
def log_blocked():
    url = request.json.get('url')
    ip_address = request.json.get('ip_address')
    user_agent = request.json.get('user_agent')
    reason = request.json.get('reason')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    log = BlockedRequest(
        url=url,
        ip_address=ip_address,
        user_agent=user_agent,
        reason=reason
    )
    
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'status': 'success'}), 201
    
@bp.route('/api/blocked/stats', methods=['GET'])
@jwt_required()
def blocked_stats():
    period = request.args.get('period', 'day')
    
    if period == 'hour':
        # Last hour
        since = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        data = db.session.query(
            db.func.count(BlockedRequest.id)
        ).filter(BlockedRequest.timestamp >= since).scalar()
        
    elif period == 'day':
        # Last 24 hours
        since = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        data = db.session.query(
            db.func.count(BlockedRequest.id)
        ).filter(BlockedRequest.timestamp >= since).scalar()
        
    elif period == 'week':
        # Last 7 days count by day
        data = db.session.query(
            db.func.date(BlockedRequest.timestamp).label('date'),
            db.func.count(BlockedRequest.id).label('count')
        ).filter(
            BlockedRequest.timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - db.text("interval '7 days'")
        ).group_by('date').all()
        
        data = {str(d[0]): d[1] for d in data}
    
    return jsonify({
        'status': 'success',
        'period': period,
        'data': data
    }), 200