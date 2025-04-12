from mitmproxy import ctx, http
from mitmproxy.tools.main import mitmdump
import os
import sys
import json
import re
import threading
import time
from urllib.parse import urlparse
import mysql.connector
from mysql.connector import Error

# Import scanners
try:
    from app.scanners.ssl_scanner import SSLScanner
    from app.scanners.malicious import EnhancedMaliciousDetector
except ImportError:
    # Add the current directory to path to fix imports
    sys.path.append(os.getcwd())
    from app.scanners.ssl_scanner import SSLScanner
    from app.scanners.malicious import EnhancedMaliciousDetector

class SiteBlocker:
    def __init__(self):
        # Initialize scanners
        self.ssl_scanner = SSLScanner()
        self.malicious_detector = EnhancedMaliciousDetector()
        
        # MySQL database configuration
        # Using the configuration from the app's config file
        self.db_config = {
            'host': 'localhost',
            'user': 'wvs_user',
            'password': 'wvs_password',
            'database': 'wvs_scanner'
        }
        
        # Cache of malicious domains for faster lookups
        self.malicious_domains = set()
        self.last_db_refresh = 0
        self.refresh_interval = 300  # Refresh every 5 minutes
        
        # Test MySQL connection before starting
        self.test_mysql_connection()
        
        # Load initial domains
        self.refresh_malicious_domains()
        
        # Start background refresh thread
        self.refresh_thread = threading.Thread(target=self.periodic_refresh, daemon=True)
        self.refresh_thread.start()
        
        ctx.log.info("Initialized site blocker with MySQL database connection")
    
    def test_mysql_connection(self):
        """Test the MySQL connection and adjust credentials if needed"""
        try:
            conn = mysql.connector.connect(**self.db_config)
            conn.close()
            ctx.log.info("MySQL connection successful with provided credentials")
        except Error as e:
            ctx.log.warn(f"MySQL connection failed with error: {str(e)}")
            
            # Try with root user as fallback (from config.py)
            try:
                import urllib.parse
                root_password = urllib.parse.unquote("@Changeme123")  # From app/config.py
                
                root_config = {
                    'host': 'localhost',
                    'user': 'root',
                    'password': root_password,
                    'database': 'wvs_scanner'
                }
                
                conn = mysql.connector.connect(**root_config)
                conn.close()
                self.db_config = root_config
                ctx.log.info("MySQL connection successful with root credentials")
            except Error as e2:
                ctx.log.error(f"All MySQL connection attempts failed: {str(e2)}")
                ctx.log.error("Make sure MySQL server is running and credentials are correct")
                # We'll continue, but will rely on local cached file
    
    def get_db_connection(self):
        """Get a MySQL database connection"""
        try:
            return mysql.connector.connect(**self.db_config)
        except Error as e:
            ctx.log.warn(f"MySQL connection failed: {str(e)}")
            return None
    
    def refresh_malicious_domains(self):
        """Load malicious domains directly from the MySQL database"""
        conn = self.get_db_connection()
        if not conn:
            # If we can't connect to the database, load from file
            self.load_from_file()
            return
        
        try:
            cursor = conn.cursor()
            
            # Query all malicious domains
            cursor.execute("SELECT domain FROM malicious_site")
            domains = [row[0] for row in cursor.fetchall()]
            
            # Update the cache
            self.malicious_domains = set(domains)
            self.last_db_refresh = time.time()
            
            cursor.close()
            conn.close()
            
            ctx.log.info(f"Loaded {len(self.malicious_domains)} malicious domains from MySQL database")
            
            # Also save to file for backup
            self.save_to_file()
            
        except Exception as e:
            ctx.log.warn(f"Error loading from database: {str(e)}")
            # Fall back to file
            self.load_from_file()
    
    def load_from_file(self):
        """Load malicious domains from JSON file as backup"""
        try:
            with open('blocked_sites.json', 'r') as f:
                data = json.load(f)
                self.malicious_domains = set(data.get('domains', []))
            
            ctx.log.info(f"Loaded {len(self.malicious_domains)} domains from backup file")
        except Exception as e:
            ctx.log.warn(f"Error loading from file: {str(e)}")
            # Initialize with empty set if all else fails
            self.malicious_domains = set()
    
    def save_to_file(self):
        """Save malicious domains to JSON file for backup"""
        try:
            with open('blocked_sites.json', 'w') as f:
                json.dump({
                    'domains': list(self.malicious_domains),
                    'patterns': [
                        ".*\\.suspicious\\.[a-z]+",
                        "temporary-[0-9]+\\.scam",
                        ".*\\.phishing\\.[a-z]+"
                    ]
                }, f)
        except Exception as e:
            ctx.log.warn(f"Error saving to file: {str(e)}")
    
    def log_blocked_request(self, url, reason, flow):
        """Log blocked request to MySQL database"""
        conn = self.get_db_connection()
        if not conn:
            ctx.log.warn("Failed to log blocked request: database connection failed")
            return
        
        try:
            cursor = conn.cursor()
            
            # Get client info
            ip_address = flow.client_conn.address[0]
            user_agent = flow.request.headers.get('User-Agent', '')
            
            # Insert record into blocked_request table
            cursor.execute(
                "INSERT INTO blocked_request (url, ip_address, user_agent, reason) VALUES (%s, %s, %s, %s)",
                (url, ip_address, user_agent, reason)
            )
            
            conn.commit()
            cursor.close()
            conn.close()
            
            ctx.log.info(f"Logged blocked request to database: {url}")
            
        except Exception as e:
            ctx.log.warn(f"Error logging to database: {str(e)}")
    
    def periodic_refresh(self):
        """Periodically refresh malicious domains from the database"""
        while True:
            try:
                time.sleep(self.refresh_interval)
                self.refresh_malicious_domains()
            except Exception as e:
                ctx.log.warn(f"Periodic refresh error: {str(e)}")
                time.sleep(60)  # Retry after 1 minute on error
    
    def is_domain_malicious(self, domain):
        """Check if domain is in malicious domain list"""
        if not domain:
            return False
        
        domain = domain.lower()
        
        # Direct match
        if domain in self.malicious_domains:
            return True
        
        # Check for subdomain matches
        domain_parts = domain.split('.')
        for i in range(len(domain_parts) - 1):
            parent_domain = '.'.join(domain_parts[i:])
            if parent_domain in self.malicious_domains:
                return True
        
        return False
    
    def is_blocked(self, url, host):
        """Check if a URL should be blocked"""
        # First check cached malicious domains (fastest)
        domain = urlparse(url).netloc.lower()
        if domain and self.is_domain_malicious(domain):
            return True, "Domain in malicious database"
            
        # Then check with malicious detector
        try:
            malicious_result = self.malicious_detector.analyze_url(url)
            if malicious_result['is_malicious']:
                reasons = []
                if malicious_result['phishing_match']:
                    reasons.append("Domain found in phishing database")
                if malicious_result['dnsbl'].get('blacklisted', False):
                    reasons.append("Domain blacklisted by DNS blocklists")
                if malicious_result['score'] >= 7:
                    reasons.append("Suspicious URL characteristics")
                    
                reason_str = " | ".join(reasons) or "Malicious site"
                
                # Add to our cache for future checks
                if domain:
                    self.malicious_domains.add(domain)
                    # Save to database asynchronously
                    threading.Thread(target=self.add_to_database, args=(url, domain, reason_str)).start()
                    
                return True, reason_str
        except Exception as e:
            ctx.log.warn(f"Error in malicious detection: {str(e)}")
            
        # If not malicious, then check SSL/TLS if it's HTTPS
        if url.startswith('https://'):
            try:
                ssl_result = self.ssl_scanner.check(url)
                if not ssl_result['valid']:
                    return True, f"Invalid SSL/TLS: {ssl_result.get('error', 'Unknown error')}"
            except Exception as e:
                ctx.log.warn(f"SSL check error: {str(e)}")
        
        return False, None
    
    def add_to_database(self, url, domain, reason):
        """Add malicious domain to MySQL database"""
        conn = self.get_db_connection()
        if not conn:
            ctx.log.warn("Failed to add malicious domain to database: connection failed")
            return
        
        try:
            cursor = conn.cursor()
            
            # Check if domain already exists
            cursor.execute("SELECT id FROM malicious_site WHERE domain = %s", (domain,))
            exists = cursor.fetchone() is not None
            
            if not exists:
                # Insert domain into malicious_site table
                cursor.execute(
                    "INSERT INTO malicious_site (domain, url, reason, source) VALUES (%s, %s, %s, %s)",
                    (domain, url, reason, "mitm_scanner")
                )
                
                conn.commit()
                ctx.log.info(f"Added malicious domain to database: {domain}")
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            ctx.log.warn(f"Error adding to database: {str(e)}")
    
    def get_block_page(self, url, reason):
        """Generate block page HTML"""
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
                .details {{
                    text-align: left;
                    background-color: #f5f5f5;
                    padding: 10px;
                    border-radius: 4px;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="warning-icon">⚠️</div>
                <h1>Security Alert - Access Blocked</h1>
                <p>This website has been blocked for your protection.</p>
                <p><strong>Reason:</strong> {reason}</p>
                <div class="details">
                    <p><strong>Requested URL:</strong> {url}</p>
                    <p>This site has been identified as potentially harmful by the Web Vulnerability Scanner.</p>
                </div>
            </div>
        </body>
        </html>
        """

# Create a global blocker object
blocker = SiteBlocker()
addons = [blocker]

def request(flow: http.HTTPFlow) -> None:
    """Handle each request"""
    # Use the global blocker
    global blocker
    
    url = flow.request.pretty_url
    host = flow.request.pretty_host
    
    # Check if the site should be blocked
    is_blocked, reason = blocker.is_blocked(url, host)
    
    if is_blocked:
        ctx.log.warn(f"🛑 Blocking access to: {host} - Reason: {reason}")
        
        # Log the blocked request
        blocker.log_blocked_request(url, reason, flow)
        
        # Return block page
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
        
        # Allow port override
        if len(sys.argv) > 1:
            try:
                port = int(sys.argv[1])
                args[5] = str(port)  # Update port in args
            except ValueError:
                pass
                
        mitmdump(args)