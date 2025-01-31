from app import db
from datetime import datetime

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    findings = db.Column(db.JSON)
    report_path = db.Column(db.String(200))