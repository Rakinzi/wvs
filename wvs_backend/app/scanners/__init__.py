from .malicious import EnhancedMaliciousDetector
from .sql_scanner import AdvancedSQLiScanner
from .ssl_scanner import SSLScanner
from .ai_scanner import AI_Scanner
from .header_scanner import HeaderScanner
from .wordpress_scanner import WordPressScanner
from .zap_scanner import ZAPScanner
from .xss_scanner import XSSScanner
from .tech_scanner import TechScanner
from .exposure_scanner import ExposureScanner
from .dns_scanner import DNSScanner
from .redirect_scanner import OpenRedirectScanner
from .takeover_scanner import SubdomainTakeoverScanner

class SecurityScanner:
    def __init__(self):
        self.malicious_detector = EnhancedMaliciousDetector()
        self.sql_scanner = AdvancedSQLiScanner()
        self.ssl_scanner = SSLScanner()
        self.ai_scanner = None
        self.header_scanner = HeaderScanner()
        self.wordpress_scanner = WordPressScanner()
        self.zap_scanner = ZAPScanner()
        self.xss_scanner = XSSScanner()
        self.tech_scanner = TechScanner()
        self.exposure_scanner = ExposureScanner()
        self.dns_scanner = DNSScanner()
        self.redirect_scanner = OpenRedirectScanner()
        self.takeover_scanner = SubdomainTakeoverScanner()

    def check_sql_injection(self, url):
        return self.sql_scanner.scan(url)

    def check_ssl(self, url):
        return self.ssl_scanner.check(url)

    def check_headers(self, url):
        return self.header_scanner.check(url)

    def check_zap(self, url):
        return self.zap_scanner.scan(url)

    def check_wordpress(self, url):
        return self.wordpress_scanner.check(url)

    def check_xss(self, url):
        return self.xss_scanner.scan(url)

    def check_tech(self, url):
        return self.tech_scanner.scan(url)

    def check_exposure(self, url):
        return self.exposure_scanner.scan(url)

    def check_dns(self, url):
        return self.dns_scanner.check(url)

    def check_redirect(self, url):
        return self.redirect_scanner.scan(url)

    def check_takeover(self, url):
        return self.takeover_scanner.scan(url)

    def check_ai(self, url):
        if self.ai_scanner is None:
            self.ai_scanner = AI_Scanner()
        return self.ai_scanner.model_predict(url)
