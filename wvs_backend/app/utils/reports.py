from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io

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
    pdf.drawString(60, y, f"Final Verdict: {'Malicious' if mal['is_malicious'] else 'Safe'}")
    
    pdf.save()
    buffer.seek(0)
    return buffer