from .malicious import EnhancedMaliciousDetector
from .sql_scanner import AdvancedSQLiScanner
from .ssl_scanner import SSLScanner

class SecurityScanner:
    def __init__(self):
        self.malicious_detector = EnhancedMaliciousDetector()
        self.sql_scanner = AdvancedSQLiScanner()
        self.ssl_scanner = SSLScanner()

    def check_sql_injection(self, url):
        return self.sql_scanner.scan(url)

    def check_ssl(self, url):
        return self.ssl_scanner.check(url)