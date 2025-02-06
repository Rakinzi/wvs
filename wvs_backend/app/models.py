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