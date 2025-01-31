# app.py
from flask import Flask, jsonify, request, send_file
from flask_sqlalchemy import SQLAlchemy
from celery import Celery
import tldextract
import re
import requests
import socket
import ssl
import certifi
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from pydnsbl import DNSBLChecker
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io
import os

app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///scans.db',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'CELERY_BROKER_URL': 'redis://localhost:6379/0',
    'CELERY_RESULT_BACKEND': 'redis://localhost:6379/0',
    'DNSBL_ENABLED': True,
    'PHISHING_DB_URL': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links/output/domains/ACTIVE/list.txt'
})

db = SQLAlchemy(app)
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime)
    findings = db.Column(db.JSON)
    report_path = db.Column(db.String(200))

class EnhancedMaliciousDetector:
    def __init__(self):
        self.dnsbl_checker = DNSBLChecker() if app.config['DNSBL_ENABLED'] else None
        self.suspicious_keywords = [
            'login', 'secure', 'account', 'verify', 'bank'
        ]
        self.shortener_domains = [
            'bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd'
        ]

    def check_dnsbl(self, domain):
        if self.dnsbl_checker:
            result = self.dnsbl_checker.check(domain)
            return {
                'detected': result.detected,
                'providers': result.detected_by,
                'total_checks': len(result.providers)
            }
        return {'detected': False}

    def check_phishing_db(self, domain):
        try:
            response = requests.get(app.config['PHISHING_DB_URL'])
            return domain in response.text
        except Exception:
            return False

    def check_hsts(self, domain):
        try:
            response = requests.head(f'https://{domain}', timeout=3)
            return 'strict-transport-security' in response.headers
        except:
            return False

    def analyze_url(self, url):
        parsed = urlparse(url)
        domain = parsed.hostname
        extracted = tldextract.extract(url)
        
        # Base heuristic checks
        score = 0
        if len(url) > 90: score += 2
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): score += 3
        if '@' in url: score += 3
        if '-' in extracted.domain: score += 1
        
        # Additional checks
        dnsbl_result = self.check_dnsbl(domain)
        phishing_match = self.check_phishing_db(domain)
        hsts_enforced = self.check_hsts(domain)
        
        return {
            'score': score,
            'dnsbl': dnsbl_result,
            'phishing_match': phishing_match,
            'hsts_enforced': hsts_enforced,
            'is_malicious': score >= 7 or dnsbl_result['detected'] or phishing_match,
            'domain_info': {
                'registered_domain': extracted.registered_domain,
                'subdomain': extracted.subdomain,
                'tld': extracted.suffix
            }
        }

class SecurityScanner:
    def __init__(self):
        self.malicious_detector = EnhancedMaliciousDetector()
        self.sql_errors = [
            'SQL syntax', 'mysql_fetch', 'syntax error',
            'unclosed quotation', 'ODBC Driver', 'ORA-'
        ]

    def check_sql_injection(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            return self._test_forms(url, soup)
        except Exception as e:
            return []

    def _test_forms(self, url, soup):
        vulnerabilities = []
        test_payloads = ["' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--"]
        
        for form in soup.find_all('form'):
            for payload in test_payloads:
                if self._test_form(form, url, payload):
                    vulnerabilities.append({
                        'form': str(form),
                        'payload': payload,
                        'severity': 'High'
                    })
        return vulnerabilities

    def _test_form(self, form, base_url, payload):
        try:
            form_data = {inp.get('name'): payload for inp in form.find_all('input')}
            action = form.get('action', base_url)
            method = form.get('method', 'get').upper()
            
            response = requests.request(
                method,
                action,
                data=form_data,
                timeout=5
            )
            
            return any(error in response.text for error in self.sql_errors)
        except Exception:
            return False

    def check_ssl(self, url):
        try:
            hostname = urlparse(url).hostname
            context = ssl.create_default_context(cafile=certifi.where())
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': cert['notAfter'],
                        'protocol': ssock.version(),
                        'self_signed': dict(x[0] for x in cert['issuer']) == dict(x[0] for x in cert['subject'])
                    }
        except Exception as e:
            return {'valid': False, 'error': str(e)}

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
        scan = save_scan(results, report_buffer)
        
        return {
            'id': scan.id,
            'url': scan.url,
            'timestamp': scan.timestamp.isoformat()
        }
    except Exception as e:
        return {'error': str(e)}

def generate_report(results):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 750, "Security Assessment Report")
    
    y = 700
    pdf.setFont("Helvetica", 12)
    
    # URL Section
    pdf.drawString(50, y, f"Scanned URL: {results['url']}")
    y -= 30
    
    # SSL Results
    pdf.drawString(50, y, "SSL/TLS Analysis:")
    y -= 20
    for key, value in results['ssl'].items():
        pdf.drawString(60, y, f"{key}: {value}")
        y -= 15
    y -= 10
    
    # SQLi Results
    pdf.drawString(50, y, f"SQL Injection Vulnerabilities Found: {len(results['sqli'])}")
    y -= 20
    for vuln in results['sqli']:
        pdf.drawString(60, y, f"- {vuln['severity']} severity vulnerability detected")
        y -= 15
    y -= 10
    
    # Malicious URL Analysis
    mal = results['malicious']
    pdf.drawString(50, y, "Malicious URL Analysis:")
    y -= 20
    pdf.drawString(60, y, f"Threat Score: {mal['score']}/10")
    y -= 15
    pdf.drawString(60, y, f"DNSBL Matches: {len(mal['dnsbl']['providers'])}/{mal['dnsbl']['total_checks']}")
    y -= 15
    pdf.drawString(60, y, f"Phishing Database Match: {mal['phishing_match']}")
    y -= 15
    pdf.drawString(60, y, f"HSTS Enforced: {mal['hsts_enforced']}")
    y -= 15
    pdf.drawString(60, y, f"Final Verdict: {'Malicious' if mal['is_malicious'] else 'Safe'}")
    
    pdf.save()
    buffer.seek(0)
    return buffer

def save_scan(results, report_buffer):
    filename = f"reports/scan_{datetime.now().timestamp()}.pdf"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    with open(filename, 'wb') as f:
        f.write(report_buffer.getbuffer())
    
    scan = ScanResult(
        url=results['url'],
        timestamp=datetime.now(),
        findings=results,
        report_path=filename
    )
    db.session.add(scan)
    db.session.commit()
    return scan

@app.route('/scan', methods=['POST'])
def start_scan():
    url = request.json.get('url')
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'Invalid URL protocol'}), 400
    
    task = scan_website.delay(url)
    return jsonify({'task_id': task.id}), 202

@app.route('/status/<task_id>', methods=['GET'])
def get_status(task_id):
    task = scan_website.AsyncResult(task_id)
    return jsonify(task.info)

@app.route('/report/<int:scan_id>', methods=['GET'])
def get_report(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return send_file(scan.report_path, mimetype='application/pdf')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)