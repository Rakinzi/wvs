from mitmproxy import ctx, http
from mitmproxy.tools.main import mitmdump
import os
import sys
import json
import re
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.malicious import EnhancedMaliciousDetector

class SiteBlocker:
    def __init__(self):
        self.ssl_scanner = SSLScanner()
        self.malicious_detector = EnhancedMaliciousDetector()
        ctx.log.info("Initialized site blocker")
    
    def is_blocked(self, url, host):
        """Check if a URL should be blocked"""
        # First check for malicious indicators
        malicious_result = self.malicious_detector.analyze_url(url)
        if malicious_result['is_malicious']:
            reasons = []
            if malicious_result['phishing_match']:
                reasons.append("Domain found in phishing database")
            if malicious_result['dnsbl'].get('blacklisted', False):
                reasons.append("Domain blacklisted by DNS blocklists")
            if malicious_result['score'] >= 7:
                reasons.append("Suspicious URL characteristics")
            return True, " | ".join(reasons)

        # If not malicious, then check SSL/TLS
        ssl_result = self.ssl_scanner.check(url)
        if not ssl_result['valid']:
            return True, f"Invalid SSL/TLS: {ssl_result.get('error', 'Unknown error')}"
        
        return False, None

    def get_block_page(self, url, reason):
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Alert - Access Blocked</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    text-align: center;
                    margin-top: 50px;
                    background-color: #f8f8f8;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                h1 {{ color: #d32f2f; }}
                .warning-icon {{
                    font-size: 60px;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="warning-icon">⚠️</div>
                <h1>Security Alert - Access Blocked</h1>
                <p>This website has been blocked for your protection.</p>
                <p><strong>Reason:</strong> {reason}</p>
                <p><strong>Requested URL:</strong> {url}</p>
            </div>
        </body>
        </html>
        """

addons = [SiteBlocker()]

def request(flow: http.HTTPFlow) -> None:
    """Handle each request"""
    blocker = ctx.master.addons.get("SiteBlocker")
    if not blocker:
        blocker = SiteBlocker()
    
    url = flow.request.pretty_url
    host = flow.request.pretty_host

    is_blocked, reason = blocker.is_blocked(url, host)
    if is_blocked:
        ctx.log.warn(f"🛑 Blocking access to: {host} - Reason: {reason}")
        flow.response = http.Response.make(
            403,  # Forbidden status code
            blocker.get_block_page(url, reason).encode('utf-8'),
            {"Content-Type": "text/html"}
        )

if __name__ == "__main__":
    if 'mitmproxy' not in sys.modules:
        args = [
            '--set', 'block_global=false',
            '--ssl-insecure',  # Accept invalid certificates
            '-s', __file__,    # This script
            '-p', '8080'       # Port to use
        ]
        mitmdump(args)