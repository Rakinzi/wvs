from celery import shared_task
from app import db
from app.scanners import SecurityScanner
from app.models import ScanResult
from app.utils.reports import generate_report
from datetime import datetime
import os

@shared_task(name='app.tasks.scan_website', bind=True)
def scan_website(self, url):
    try:
        scanner = SecurityScanner()
        
        results = {
            'url': url,
            'sqli': scanner.check_sql_injection(url),
            'ssl': scanner.check_ssl(url),
            'malicious': scanner.malicious_detector.analyze_url(url),
            'timestamp': datetime.now().isoformat()
        }
        
        report_buffer = generate_report(results)
        filename = f"reports/scan_{datetime.now().timestamp()}.pdf"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'wb') as f:
            f.write(report_buffer.getbuffer())

        try:
            scan = ScanResult(
                url=results['url'],
                findings=results,
                report_path=filename
            )
            
            db.session.add(scan)
            db.session.commit()
            
            return {
                'status': 'success',
                'id': scan.id,
                'url': scan.url,
                'timestamp': scan.timestamp.isoformat()
            }
        except Exception as db_error:
            if db.session:
                db.session.rollback()
            raise db_error
            
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }