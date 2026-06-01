from flask import Blueprint, jsonify, request
from app.auth import get_current_user
from app.models import MaliciousSite, BlockedRequest
from app.schemas import AddMaliciousPayload, BlockedLogPayload
from app.utils.db_manager import DBManager
from flask_jwt_extended import jwt_required
from app.utils.scan_helpers import normalize_target_url
from app import db, limiter
from datetime import datetime
from pydantic import ValidationError
from app.utils.time_utils import utc_now

bp = Blueprint('malicious', __name__)

@bp.route('/api/malicious/check', methods=['GET'])
@limiter.limit("30 per hour")
def check_malicious():
    try:
        url = normalize_target_url(request.args.get('url'))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
        
    # Check database first (fastest)
    is_blocked, reason = DBManager.check_malicious_url(url)
    
    if is_blocked:
        return jsonify({
            'url': url,
            'blocked': True,
            'reason': reason or 'Domain in database',
            'source': 'database',
        }), 200
    
    # If not in database, use the malicious detector
    from app.scanners import SecurityScanner

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
            'details': malicious_result,
            'source': 'rule_engine',
        }), 200
    
    # Run AI prediction as a final check
    try:
        prediction_int, prediction_label, prediction_source = scanner.check_ai(url)
        if prediction_label in ["phishing", "malware", "defacement"]:
            reason_str = f"AI classified as {prediction_label}"
            DBManager.add_malicious_url(url, reason_str, "ai")
            return jsonify({
                'url': url,
                'blocked': True,
                'reason': reason_str,
                'source': prediction_source,
                'ai': {
                    'backend': prediction_source,
                    'label': prediction_label,
                    'prediction': prediction_int,
                },
            }), 200
    except Exception:
        pass
        
    return jsonify({
        'url': url,
        'blocked': False,
        'source': 'none',
    }), 200

@bp.route('/api/malicious/list', methods=['GET'])
@jwt_required()
@limiter.limit("30 per hour")
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
    
    return jsonify({
        'count': len(sites),
        'domains': [site.domain for site in sites],
        'sites': [site.to_dict() for site in sites],
    }), 200

@bp.route('/api/malicious/add', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
def add_malicious():
    try:
        payload = AddMaliciousPayload.model_validate(request.get_json(silent=True) or {})
        reason = payload.reason
        url = normalize_target_url(payload.url)
    except (ValueError, ValidationError) as exc:
        return jsonify({'error': str(exc)}), 400
        
    success = DBManager.add_malicious_url(url, reason, "manual")
    
    if success:
        return jsonify({'status': 'success', 'message': 'URL added to malicious database'}), 201
    else:
        return jsonify({'status': 'warning', 'message': 'URL already exists in database'}), 200
        
@bp.route('/api/blocked/log', methods=['POST'])
@limiter.limit("60 per hour")
def log_blocked():
    try:
        payload = BlockedLogPayload.model_validate(request.get_json(silent=True) or {})
        url = normalize_target_url(payload.url)
    except (ValueError, ValidationError) as exc:
        return jsonify({'error': str(exc)}), 400
    ip_address = payload.ip_address
    user_agent = payload.user_agent
    reason = payload.reason
        
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
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403

    period = request.args.get('period', 'day')
    
    if period == 'hour':
        # Last hour
        since = utc_now().replace(minute=0, second=0, microsecond=0)
        data = db.session.query(
            db.func.count(BlockedRequest.id)
        ).filter(BlockedRequest.timestamp >= since).scalar()
        
    elif period == 'day':
        # Last 24 hours
        since = utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
        data = db.session.query(
            db.func.count(BlockedRequest.id)
        ).filter(BlockedRequest.timestamp >= since).scalar()
        
    elif period == 'week':
        # Last 7 days count by day
        data = db.session.query(
            db.func.date(BlockedRequest.timestamp).label('date'),
            db.func.count(BlockedRequest.id).label('count')
        ).filter(
            BlockedRequest.timestamp >= utc_now().replace(hour=0, minute=0, second=0, microsecond=0) - db.text("interval '7 days'")
        ).group_by('date').all()
        
        data = {str(d[0]): d[1] for d in data}
    
    return jsonify({
        'status': 'success',
        'period': period,
        'data': data
    }), 200
