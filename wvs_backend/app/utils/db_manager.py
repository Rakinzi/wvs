from app import db
from app.models import MaliciousSite, ScanResult, User
from urllib.parse import urlparse
import os
from app.utils.time_utils import utc_now

class DBManager:
    @staticmethod
    def check_malicious_url(url):
        domain = urlparse(url).netloc
        if not domain:
            domain = urlparse("http://" + url).netloc
            
        existing = MaliciousSite.query.filter_by(domain=domain).first()
        return existing is not None, existing.reason if existing else None
    
    @staticmethod
    def add_malicious_url(url, reason="", source="scan"):
        domain = urlparse(url).netloc
        if not domain:
            domain = urlparse("http://" + url).netloc
            
        existing = MaliciousSite.query.filter_by(domain=domain).first()
        if not existing:
            site = MaliciousSite(
                domain=domain,
                url=url,
                reason=reason,
                source=source,
                date_added=utc_now()
            )
            db.session.add(site)
            db.session.commit()
            return True
        return False
    
    @staticmethod
    def get_user_scans(user_id, limit=20):
        scan_ids = [
            row.id
            for row in ScanResult.query.with_entities(ScanResult.id)
            .filter(ScanResult.user_id == user_id)
            .order_by(ScanResult.timestamp.desc())
            .limit(limit)
            .all()
        ]
        if not scan_ids:
            return []

        order = {scan_id: index for index, scan_id in enumerate(scan_ids)}
        scans = ScanResult.query.filter(ScanResult.id.in_(scan_ids)).all()
        return sorted(scans, key=lambda scan: order.get(scan.id, len(order)))
    
    @staticmethod
    def get_user_by_username(username):
        return User.query.filter_by(username=username).first()
    
    @staticmethod
    def save_scan_result(url, findings, report_path, user_id):
        # Convert report_path to absolute path if it's not already
        if not os.path.isabs(report_path):
            report_path = os.path.abspath(report_path)
            
        # Ensure the containing directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        scan = ScanResult(
            url=url,
            findings=findings,
            report_path=report_path,
            user_id=user_id
        )
        db.session.add(scan)
        db.session.commit()
        
        # Log the saved path for debugging
        print(f"Saved scan result with report path: {report_path}")
        
        return scan
