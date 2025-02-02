from app import celery, db
from app.scanners import SecurityScanner
from app.utils.reports import generate_report
from datetime import datetime
from .models import ScanResult
import os

@celery.task
def scan_website(url):
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
        
        scan = ScanResult(
            url=results['url'],
            findings=results,
            report_path=filename
        )
        db.session.add(scan)
        db.session.commit()
        
        return {
            'id': scan.id,
            'url': scan.url,
            'timestamp': scan.timestamp.isoformat()
        }
    except Exception as e:
        return {'error': str(e)}