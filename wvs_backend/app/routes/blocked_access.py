from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from app.auth import get_current_user
from app.models import BlockedRequest
from app import db
from datetime import timedelta
from urllib.parse import urlparse
from app.utils.time_utils import utc_now

bp = Blueprint('blocked_access', __name__)

@bp.route('/blocked-access/list', methods=['GET'])
@jwt_required()
def get_blocked_access():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
            
        # Check if user is admin
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized access'}), 403
            
        # Get query parameters
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Query blocked requests
        blocked_requests = BlockedRequest.query.order_by(
            BlockedRequest.timestamp.desc()
        ).limit(limit).offset(offset).all()
        
        # Format results
        results = []
        for blocked in blocked_requests:
            results.append({
                'id': blocked.id,
                'url': blocked.url,
                'ip_address': blocked.ip_address,
                'user_agent': blocked.user_agent,
                'timestamp': blocked.timestamp.isoformat(),
                'reason': blocked.reason
            })
        
        # Get total count
        total_count = BlockedRequest.query.count()
        
        return jsonify({
            'status': 'success',
            'blocked_requests': results,
            'total': total_count,
            'limit': limit,
            'offset': offset
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
        
@bp.route('/blocked-access/stats', methods=['GET'])
@jwt_required()
def get_blocked_access_stats():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
            
        # Check if user is admin
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized access'}), 403
        
        # Get stats for the past 7 days
        seven_days_ago = utc_now() - timedelta(days=7)
        
        # Count attempts by day
        attempts_by_day = db.session.query(
            db.func.date(BlockedRequest.timestamp).label('date'),
            db.func.count(BlockedRequest.id).label('count')
        ).filter(
            BlockedRequest.timestamp >= seven_days_ago
        ).group_by(
            db.func.date(BlockedRequest.timestamp)
        ).all()
        
        # Format results for past 7 days (fill in missing days with 0)
        days_data = []
        for i in range(7):
            day = (utc_now() - timedelta(days=i)).date()
            # Find count for this day, or default to 0
            count = 0
            for attempt_day, attempt_count in attempts_by_day:
                if hasattr(attempt_day, 'date'):
                    attempt_day = attempt_day.date()
                if attempt_day == day:
                    count = attempt_count
                    break
            days_data.append({
                'date': day.isoformat(),
                'count': count
            })
        
        # Get total counts
        total_blocked = BlockedRequest.query.count()
        today_blocked = BlockedRequest.query.filter(
            BlockedRequest.timestamp >= utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
        ).count()
        
        # Get counts by browser
        browser_counts = []
        # We'll extract browser info from user agent string on the server side
        # In a real implementation, this would be done with a proper user agent parser
        # For demonstration, we'll check for common browser strings
        for browser in ['Firefox', 'Chrome', 'Safari', 'Edge', 'MSIE', 'Opera']:
            count = BlockedRequest.query.filter(
                BlockedRequest.user_agent.ilike(f'%{browser}%')
            ).count()
            if count > 0:
                browser_counts.append({
                    'browser': browser,
                    'count': count
                })
        
        # Get most blocked domains
        top_domains = []
        # In a real implementation, this would extract the domain from the URL
        # For demonstration, we'll just group by URL
        domain_results = db.session.query(
            BlockedRequest.url,
            db.func.count(BlockedRequest.id).label('count')
        ).group_by(
            BlockedRequest.url
        ).order_by(
            db.func.count(BlockedRequest.id).desc()
        ).limit(10).all()
        
        for url, count in domain_results:
            try:
                domain = urlparse(url).netloc
                if domain:
                    top_domains.append({
                        'domain': domain,
                        'count': count
                    })
            except Exception:
                # Skip invalid URLs
                pass
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_blocked': total_blocked,
                'today_blocked': today_blocked,
                'days_data': days_data,
                'browser_counts': browser_counts,
                'top_domains': top_domains
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/dashboard/recent-blocked', methods=['GET'])
@jwt_required()
def get_recent_blocked():
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404

        if not current_user.is_admin:
            return jsonify({
                'status': 'success',
                'recent_blocked': []
            }), 200
        
        # Get recent blocked requests
        recent_blocked = BlockedRequest.query.order_by(
            BlockedRequest.timestamp.desc()
        ).limit(5).all()
        
        # Format results
        results = []
        for blocked in recent_blocked:
            results.append({
                'id': blocked.id,
                'url': blocked.url,
                'ip_address': blocked.ip_address,
                'user_agent': blocked.user_agent,
                'timestamp': blocked.timestamp.isoformat(),
                'reason': blocked.reason
            })
        
        return jsonify({
            'status': 'success',
            'recent_blocked': results
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
