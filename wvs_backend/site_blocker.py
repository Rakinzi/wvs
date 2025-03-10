from mitmproxy import ctx, http
from mitmproxy.tools.main import mitmdump
import os
import sys
import json
import re

class SiteBlocker:
    def __init__(self):
        self.blocked_domains = [
            "github.com",
            "phishing-example.org",
            "malware-distribution.net",
            "example-scam.com"
        ]
        
        self.blocked_patterns = [
            r".*\.evil$",
            r"suspicious-[0-9]+\.com"
        ]
        
        self.load_blocked_domains()
        ctx.log.info(f"Initialized site blocker with {len(self.blocked_domains)} domains and {len(self.blocked_patterns)} patterns")
    
    def load_blocked_domains(self):
        blocklist_file = os.path.join(os.path.dirname(__file__), "blocked_sites.json")
        if os.path.exists(blocklist_file):
            try:
                with open(blocklist_file, 'r') as f:
                    data = json.load(f)
                    if "domains" in data:
                        self.blocked_domains.extend(data["domains"])
                    if "patterns" in data:
                        self.blocked_patterns.extend(data["patterns"])
                ctx.log.info(f"Loaded additional blocklist from {blocklist_file}")
            except Exception as e:
                ctx.log.error(f"Error loading blocklist: {e}")
    
    def is_blocked(self, host):
        """Check if a host should be blocked"""
        # Remove http:// or https:// from the host
        host = re.sub(r'^https?://', '', host)
        
        # Direct domain match
        if any(domain in host or host.endswith('.' + domain) for domain in self.blocked_domains):
            ctx.log.info(f"Blocked by domain match: {host}")
            return True
                
        # Regex pattern match
        if any(re.match(pattern, host) for pattern in self.blocked_patterns):
            ctx.log.info(f"Blocked by pattern match: {host}")
            return True
                
        return False

    def get_block_page(self, url):
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Site Blocked</title></head>
        <body style="font-family: Arial; text-align: center; margin-top: 50px;">
            <h1 style="color: red;">Access Blocked</h1>
            <p>This website has been blocked for your protection.</p>
            <p>Requested URL: {}</p>
        </body>
        </html>
        """.format(url)

addons = [
    SiteBlocker()
]

def request(flow: http.HTTPFlow) -> None:
    """
    Handle each request
    """
    blocker = ctx.master.addons.get("SiteBlocker")
    if not blocker:
        blocker = SiteBlocker()
        
    host = flow.request.pretty_host
    url = flow.request.url
    
    if blocker.is_blocked(host):
        ctx.log.warn(f"🛑 Blocking access to: {host}")
        flow.response = http.Response.make(
            403,  # Forbidden status code
            blocker.get_block_page(url).encode('utf-8'),
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