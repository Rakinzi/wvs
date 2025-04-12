from mitmproxy import ctx, http
from mitmproxy.tools.main import mitmdump
import os
import sys
import json
import re
import socket
import requests
from urllib.parse import urlparse
import threading
import time
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
import logging

class SiteBlocker:
    def __init__(self):
        self.db_initialized = False
        self.malicious_domains = set()
        self.pattern_blacklist = []
        self.last_refresh = 0
        self.refresh_interval = 300  # 5 minutes
        
        # Load initial blacklist
        self.load_blacklist()
        
        # Start background thread for DB updates
        threading.Thread(target=self.periodic_refresh, daemon=True).start()
        
        ctx.log.info("Initialized site blocker with local database")
    
    def load_blacklist(self):
        try:
            # Load from JSON file for quick startup
            with open('blocked_sites.json', 'r') as f:
                data = json.load(f)
                self.malicious_domains = set(data.get('domains', []))
                self.pattern_blacklist = [re.compile(pattern) for pattern in data.get('patterns', [])]
                
            ctx.log.info(f"Loaded {len(self.malicious_domains)} domains and {len(self.pattern_blacklist)} patterns from file")
        except Exception as e:
            ctx.log.warn(f"Error loading blacklist file: {str(e)}")
    
    def refresh_from_db(self):
        if not self.db_initialized:
            try:
                # Try to connect to the database
                response = requests.get("http://localhost:5000/api/malicious/list", timeout=2)
                if response.status_code == 200:
                    domains = response.json().get('domains', [])
                    self.malicious_domains = set(domains)
                    ctx.log.info(f"Refreshed {len(self.malicious_domains)} domains from database")
                    self.db_initialized = True
                    return True
            except Exception as e:
                ctx.log.warn(f"Database connection failed: {str(e)}")
                return False
        else:
            try:
                # Get only new domains since last refresh
                response = requests.get(f"http://localhost:5000/api/malicious/list?since={self.last_refresh}", timeout=2)
                if response.status_code == 200:
                    new_domains = response.json().get('domains', [])
                    self.malicious_domains.update(new_domains)
                    ctx.log.info(f"Added {len(new_domains)} new domains from database")
                return True
            except Exception as e:
                ctx.log.warn(f"Database refresh failed: {str(e)}")
                return False
    
    def periodic_refresh(self):
        while True:
            time.sleep(self.refresh_interval)
            self.refresh_from_db()
            self.last_refresh = int(time.time())
    
    def is_domain_blocked(self, domain):
        # Check exact match
        if domain in self.malicious_domains:
            return True, "Domain in blacklist"
        
        # Check pattern match
        for pattern in self.pattern_blacklist:
            if pattern.match(domain):
                return True, f"Matches pattern: {pattern.pattern}"
        
        return False, None
    
    def is_blocked(self, url, host):
        domain = urlparse(url).netloc
        
        # First check local cache
        is_blocked, reason = self.is_domain_blocked(domain)
        if is_blocked:
            return True, reason
        
        # If not in local cache, check database
        try:
            response = requests.get(f"http://localhost:5000/api/malicious/check?url={url}", timeout=1)
            if response.status_code == 200 and response.json().get('blocked', False):
                self.malicious_domains.add(domain)  # Add to local cache
                return True, response.json().get('reason', 'Blocked by database check')
        except Exception:
            pass  # Continue if API is not available
        
        return False, None

    def log_blocked_request(self, url, reason, flow):
        try:
            requests.post("http://localhost:5000/api/blocked/log", json={
                'url': url,
                'ip_address': flow.client_conn.address[0],
                'user_agent': flow.request.headers.get('User-Agent', ''),
                'reason': reason
            }, timeout=1)
        except Exception:
            pass  # Don't fail if logging fails
    
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

def request(flow: http.HTTPFlow) -> None:
    blocker = ctx.master.addons.get("SiteBlocker")
    if not blocker:
        blocker = SiteBlocker()
        ctx.master.addons.register(blocker)
    
    url = flow.request.pretty_url
    host = flow.request.pretty_host

    is_blocked, reason = blocker.is_blocked(url, host)
    if is_blocked:
        ctx.log.warn(f"🛑 Blocking access to: {host} - Reason: {reason}")
        
        # Log the blocked request
        blocker.log_blocked_request(url, reason, flow)
        
        flow.response = http.Response.make(
            403,  # Forbidden status code
            blocker.get_block_page(url, reason).encode('utf-8'),
            {"Content-Type": "text/html"}
        )

addons = [SiteBlocker()]

if __name__ == "__main__":
    if 'mitmproxy' not in sys.modules:
        args = [
            '--set', 'block_global=false',
            '--ssl-insecure',  # Accept invalid certificates
            '-s', __file__,    # This script
            '-p', '8080'       # Port to use
        ]
        mitmdump(args)