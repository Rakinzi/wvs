from celery import shared_task
from app import db
from app.scanners import SecurityScanner
from app.models import ScanResult, MaliciousSite
from app.utils.reports import generate_report
from app.utils.db_manager import DBManager
from datetime import datetime
import os
from urllib.parse import urlparse
import time

@shared_task(name='app.tasks.scan_website', bind=True)
def scan_website(self, url, user_id=None):
    try:
        start_time = time.time()
        scanner = SecurityScanner()
        
        # Check if URL is already known to be malicious
        is_malicious, reason = DBManager.check_malicious_url(url)
        if is_malicious:
            return {
                'status': 'error',
                'message': f'URL is flagged as malicious: {reason}',
                'is_malicious': True
            }
        
        results = {
            'url': url,
            'sqli': scanner.check_sql_injection(url),
            'ssl': scanner.check_ssl(url),
            'malicious': scanner.malicious_detector.analyze_url(url),
            'timestamp': datetime.utcnow().isoformat(),
            'scan_time': round(time.time() - start_time, 2)
        }
        
        # If the site is malicious, add to database for future checks
        if results['malicious']['is_malicious']:
            reason = []
            if results['malicious']['phishing_match']:
                reason.append("Phishing site")
            if results['malicious']['dnsbl'].get('blacklisted', False):
                reason.append("Listed in DNS blacklists")
            if results['malicious']['score'] >= 7:
                reason.append("Suspicious URL characteristics")
                
            reason_str = " | ".join(reason) or "Malicious site"
            DBManager.add_malicious_url(url, reason_str, "scan")
        
        # Generate report
        report_buffer = generate_report(results)
        filename = f"reports/scan_{datetime.utcnow().timestamp()}.pdf"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'wb') as f:
            f.write(report_buffer.getbuffer())
        
        # Save to database if user_id is provided
        if user_id:
            scan_id = DBManager.save_scan_result(
                url=results['url'],
                findings=results,
                report_path=filename,
                user_id=user_id
            )
            results['scan_id'] = scan_id
            
        return {
            'status': 'success',
            'url': url,
            'findings': results,
            'report_path': filename,
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        if db.session:
            db.session.rollback()
        return {
            'status': 'error',
            'message': str(e)
        }