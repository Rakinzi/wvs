from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    findings = db.Column(db.JSON)
    report_path = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('scans', lazy=True))
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    
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