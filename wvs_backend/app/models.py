from app import db
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from app.utils.time_utils import utc_now

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    url = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=utc_now)
    findings = db.Column(db.JSON)
    report_path = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('scans', lazy=True))


class ScanJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False, default='full')
    status = db.Column(db.String(30), nullable=False, default='queued', index=True)
    task_id = db.Column(db.String(100), unique=True)
    findings = db.Column(db.JSON)
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'))
    user = db.relationship('User', backref=db.backref('scan_jobs', lazy=True))
    result = db.relationship('ScanResult', backref=db.backref('scan_job', uselist=False))

    def to_dict(self):
        return {
            'id': self.public_id,
            'url': self.url,
            'scan_type': self.scan_type,
            'status': self.status,
            'task_id': self.task_id,
            'findings': self.findings,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'user_id': self.user_id,
            'result_id': self.result.public_id if self.result else None,
        }
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_on = db.Column(db.DateTime, default=utc_now)
    reset_token_hash = db.Column(db.String(64), nullable=True, index=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)
    reset_requested_at = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_token_hash = db.Column(db.String(64), nullable=True, index=True)
    verification_token_expires_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)

class MaliciousSite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), index=True, unique=True)
    url = db.Column(db.String(500))
    reason = db.Column(db.String(255), default="")
    source = db.Column(db.String(50), default="scan")
    date_added = db.Column(db.DateTime, default=utc_now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'url': self.url,
            'reason': self.reason,
            'source': self.source,
            'date_added': self.date_added.isoformat()
        }

class BlockedRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=utc_now)
    reason = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<BlockedRequest {self.url}>'


class VerifiedTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    target_url = db.Column(db.String(500), nullable=False)
    normalized_domain = db.Column(db.String(255), nullable=False, index=True)
    verification_method = db.Column(db.String(50), nullable=False, default='meta_tag')
    verification_token_hash = db.Column(db.String(64), nullable=False, index=True)
    verification_token = db.Column(db.String(128), nullable=True)
    verification_status = db.Column(db.String(30), nullable=False, default='pending', index=True)
    verified_at = db.Column(db.DateTime)
    token_expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('verified_targets', lazy=True))

    def to_dict(self):
        return {
            'id': self.public_id,
            'target_url': self.target_url,
            'normalized_domain': self.normalized_domain,
            'verification_method': self.verification_method,
            'verification_status': self.verification_status,
            'verification_token': self.verification_token,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None,
            'token_expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_id': self.user_id,
        }


class UptimeMonitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    name = db.Column(db.String(120), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(30), nullable=False, default='pending', index=True)
    check_interval_minutes = db.Column(db.Integer, nullable=False, default=5)
    is_enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    last_checked_at = db.Column(db.DateTime)
    last_up_at = db.Column(db.DateTime)
    last_response_time_ms = db.Column(db.Integer)
    consecutive_failures = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('uptime_monitors', lazy=True))

    def to_dict(self):
        return {
            'id': self.public_id,
            'name': self.name,
            'target_url': self.target_url,
            'status': self.status,
            'check_interval_minutes': self.check_interval_minutes,
            'is_enabled': self.is_enabled,
            'last_checked_at': self.last_checked_at.isoformat() if self.last_checked_at else None,
            'last_up_at': self.last_up_at.isoformat() if self.last_up_at else None,
            'last_response_time_ms': self.last_response_time_ms,
            'consecutive_failures': self.consecutive_failures,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_id': self.user_id,
        }


class UptimeCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    status = db.Column(db.String(20), nullable=False, index=True)
    status_code = db.Column(db.Integer)
    response_time_ms = db.Column(db.Integer)
    error_message = db.Column(db.Text)
    checked_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    monitor_id = db.Column(db.Integer, db.ForeignKey('uptime_monitor.id'), nullable=False, index=True)
    monitor = db.relationship(
        'UptimeMonitor',
        backref=db.backref('checks', lazy=True, cascade='all, delete-orphan', order_by='desc(UptimeCheck.checked_at)'),
    )

    def to_dict(self):
        return {
            'id': self.public_id,
            'status': self.status,
            'status_code': self.status_code,
            'response_time_ms': self.response_time_ms,
            'error_message': self.error_message,
            'checked_at': self.checked_at.isoformat() if self.checked_at else None,
            'monitor_id': self.monitor.public_id if self.monitor else None,
        }
