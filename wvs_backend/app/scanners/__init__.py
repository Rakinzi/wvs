from .malicious import EnhancedMaliciousDetector
from .sql import SQLInjectionScanner
from .ssl import SSLScanner

class SecurityScanner:
    def __init__(self):
        self.malicious_detector = EnhancedMaliciousDetector()
        self.sql_scanner = SQLInjectionScanner()
        self.ssl_scanner = SSLScanner()

    def check_sql_injection(self, url):
        return self.sql_scanner.check(url)

    def check_ssl(self, url):
        return self.ssl_scanner.check(url)