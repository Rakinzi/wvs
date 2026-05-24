from app import db
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    url = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
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
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))
    email = db.Column(db.String(100), unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    reset_token_hash = db.Column(db.String(64), nullable=True, index=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)
    reset_requested_at = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_token_hash = db.Column(db.String(64), nullable=True, index=True)
    
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
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
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
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<BlockedRequest {self.url}>'
