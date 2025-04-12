from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from reportlab.lib.units import inch
import io
from datetime import datetime

def generate_report(results):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Set up document
    pdf.setTitle(f"Security Assessment Report - {results['url']}")
    
    # Header
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(50, height - 50, "Web Vulnerability Scanner - Security Report")
    
    # Date and URL
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, height - 70, f"Scan Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    
    # Horizontal line
    pdf.setStrokeColor(colors.gray)
    pdf.line(50, height - 80, width - 50, height - 80)
    
    # URL Section
    y = height - 100
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Target Information")
    y -= 20
    
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, y, f"Scanned URL: {results['url']}")
    y -= 30
    
    # Executive Summary
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Executive Summary")
    y -= 20
    
    # Count vulnerabilities
    sql_issues = len(results['sqli'])
    ssl_issues = 0 if results['ssl'].get('valid', True) else 1
    is_malicious = results['malicious'].get('is_malicious', False)
    
    total_issues = sql_issues + ssl_issues + (1 if is_malicious else 0)
    
    pdf.setFont("Helvetica", 11)
    pdf.drawString(50, y, f"Total vulnerabilities found: {total_issues}")
    y -= 15
    
    if total_issues > 0:
        if sql_issues > 0:
            pdf.drawString(60, y, f"- SQL Injection vulnerabilities: {sql_issues}")
            y -= 15
        if ssl_issues > 0:
            pdf.drawString(60, y, f"- SSL/TLS issues: {ssl_issues}")
            y -= 15
        if is_malicious:
            pdf.drawString(60, y, f"- Site flagged as potentially malicious")
            y -= 15
    else:
        pdf.drawString(60, y, "No critical vulnerabilities detected in this scan")
        y -= 15
    
    y -= 20
    
    # Risk Rating
    risk_level = "Low"
    if total_issues > 5 or is_malicious:
        risk_level = "Critical"
    elif total_issues > 3:
        risk_level = "High"
    elif total_issues > 0:
        risk_level = "Medium"
    
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, f"Overall Risk Rating: {risk_level}")
    y -= 30
    
    # Detailed Results
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Detailed Scan Results")
    y -= 30
    
    # SSL Results
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "SSL/TLS Analysis:")
    y -= 20
    
    pdf.setFont("Helvetica", 10)
    
    if results['ssl'].get('valid', False):
        pdf.drawString(60, y, "✓ Valid SSL/TLS certificate found")
        y -= 15
        for key, value in results['ssl'].items():
            if key not in ['valid', 'error'] and value:
                if isinstance(value, dict):
                    # For nested dicts like 'issuer' and 'subject'
                    pdf.drawString(70, y, f"{key.capitalize()}:")
                    y -= 15
                    for subkey, subvalue in value.items():
                        pdf.drawString(80, y, f"{subkey}: {subvalue}")
                        y -= 15
                else:
                    pdf.drawString(70, y, f"{key.capitalize()}: {value}")
                    y -= 15
    else:
        pdf.setFillColor(colors.red)
        pdf.drawString(60, y, "✗ SSL/TLS certificate issue detected")
        pdf.setFillColor(colors.black)
        y -= 15
        error = results['ssl'].get('error', 'Unknown SSL error')
        pdf.drawString(70, y, f"Error: {error}")
        y -= 15
        
        # Recommendations
        pdf.drawString(70, y, "Recommendations:")
        y -= 15
        pdf.drawString(80, y, "- Obtain a valid SSL certificate from a trusted CA")
        y -= 15
        pdf.drawString(80, y, "- Ensure proper SSL/TLS configuration")
        y -= 15
        pdf.drawString(80, y, "- Use modern TLS protocols (TLS 1.2+)")
        y -= 15
    
    y -= 10
    
    # SQLi Results
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, f"SQL Injection Analysis:")
    y -= 20
    
    pdf.setFont("Helvetica", 10)
    if not results['sqli']:
        pdf.drawString(60, y, "✓ No SQL Injection vulnerabilities detected")
        y -= 15
    else:
        pdf.setFillColor(colors.red)
        pdf.drawString(60, y, f"✗ SQL Injection vulnerabilities found: {len(results['sqli'])}")
        pdf.setFillColor(colors.black)
        y -= 15
        
        # Only show details for first 3 vulnerabilities to save space
        for i, vuln in enumerate(results['sqli'][:3]):
            pdf.drawString(70, y, f"Vulnerability {i+1}:")
            y -= 15
            pdf.drawString(80, y, f"Type: {vuln.get('type', 'Unknown')}")
            y -= 15
            pdf.drawString(80, y, f"Severity: {vuln.get('severity', 'Unknown')}")
            y -= 15
            pdf.drawString(80, y, f"Parameter: {vuln.get('parameter', 'Unknown')}")
            y -= 15
            
        # Recommendations
        pdf.drawString(70, y, "Recommendations:")
        y -= 15
        pdf.drawString(80, y, "- Use parameterized queries or prepared statements")
        y -= 15
        pdf.drawString(80, y, "- Implement input validation and sanitization")
        y -= 15
        pdf.drawString(80, y, "- Apply least privilege principle for database users")
        y -= 15
    
    y -= 10
    
    # Malicious URL Analysis
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Malicious URL Analysis:")
    y -= 20
    
    pdf.setFont("Helvetica", 10)
    mal = results['malicious']
    
    if not mal.get('is_malicious', False):
        pdf.drawString(60, y, "✓ URL not identified as malicious")
        y -= 15
        pdf.drawString(70, y, f"Threat Score: {mal.get('score', 0)}/10")
        y -= 15
    else:
        pdf.setFillColor(colors.red)
        pdf.drawString(60, y, "✗ URL identified as potentially malicious")
        pdf.setFillColor(colors.black)
        y -= 15
        pdf.drawString(70, y, f"Threat Score: {mal.get('score', 0)}/10")
        y -= 15
        
        if mal.get('phishing_match', False):
            pdf.drawString(70, y, "✗ URL matches known phishing patterns")
            y -= 15
            
        dnsbl = mal.get('dnsbl', {})
        blacklists = dnsbl.get('total_detected', 0)
        if blacklists > 0:
            pdf.drawString(70, y, f"✗ Listed in {blacklists} DNS blacklists")
            y -= 15
        
        # Recommendations
        pdf.drawString(70, y, "Recommendations:")
        y -= 15
        pdf.drawString(80, y, "- Do not proceed to this website")
        y -= 15
        pdf.drawString(80, y, "- If this is your site, investigate potential compromise")
        y -= 15
        pdf.drawString(80, y, "- Contact your security team immediately")
        y -= 15
    
    # Footer
    pdf.setFont("Helvetica-Oblique", 8)
    pdf.drawString(50, 30, "This report was automatically generated and should be reviewed by security professionals.")
    pdf.drawString(50, 20, "False positives may occur. Additional manual testing is recommended for critical systems.")
    
    pdf.save()
    buffer.seek(0)
    return buffer