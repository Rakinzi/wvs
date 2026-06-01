from .malicious import EnhancedMaliciousDetector
from .sql_scanner import AdvancedSQLiScanner
from .ssl_scanner import SSLScanner
from .ai_scanner import AI_Scanner
from .header_scanner import HeaderScanner
from .wordpress_scanner import WordPressScanner
from .zap_scanner import ZAPScanner
from .nikto_scanner import NiktoScanner
from .xss_scanner import XSSScanner
from .tech_scanner import TechScanner
from .exposure_scanner import ExposureScanner, SecretScanner
from .dns_scanner import DNSScanner
from .redirect_scanner import OpenRedirectScanner
from .takeover_scanner import SubdomainTakeoverScanner
from .accessibility_scanner import AccessibilityScanner
from .responsive_scanner import ResponsiveScanner
from .performance_ux_scanner import PerformanceUXScanner
from .form_usability_scanner import FormUsabilityScanner
from .visual_ai_scanner import VisualAIScanner
from .malware_scanner import MalwareAnalysisScanner
from .screenshot_scanner import ScreenshotScanner
from .seo_scanner import SEOScanner
from .abuse_controls_scanner import AbuseControlsScanner
from .broken_link_scanner import BrokenLinkScanner
from .app_controls_scanner import AppControlsScanner
from .exposed_services_scanner import ExposedServicesScanner
from .ssrf_scanner import SSRFScanner
from .logging_monitor_scanner import LoggingMonitorScanner
from .auth_scanner import AuthScanner
from .integrity_scanner import IntegrityScanner

class SecurityScanner:
    def __init__(self):
        self.malicious_detector = EnhancedMaliciousDetector()
        self.sql_scanner = AdvancedSQLiScanner()
        self.ssl_scanner = SSLScanner()
        self.ai_scanner = None
        self.header_scanner = HeaderScanner()
        self.wordpress_scanner = WordPressScanner()
        self.zap_scanner = ZAPScanner()
        self.nikto_scanner = NiktoScanner()
        self.xss_scanner = XSSScanner()
        self.tech_scanner = TechScanner()
        self.exposure_scanner = ExposureScanner()
        self.secret_scanner = SecretScanner()
        self.dns_scanner = DNSScanner()
        self.redirect_scanner = OpenRedirectScanner()
        self.takeover_scanner = SubdomainTakeoverScanner()
        self.accessibility_scanner = AccessibilityScanner()
        self.responsive_scanner = ResponsiveScanner()
        self.performance_ux_scanner = PerformanceUXScanner()
        self.form_usability_scanner = FormUsabilityScanner()
        self.visual_ai_scanner = VisualAIScanner()
        self.malware_scanner = MalwareAnalysisScanner()
        self.screenshot_scanner = ScreenshotScanner()
        self.seo_scanner = SEOScanner()
        self.abuse_controls_scanner = AbuseControlsScanner()
        self.broken_link_scanner = BrokenLinkScanner()
        self.app_controls_scanner = AppControlsScanner()
        self.exposed_services_scanner = ExposedServicesScanner()
        self.ssrf_scanner = SSRFScanner()
        self.logging_monitor_scanner = LoggingMonitorScanner()
        self.auth_scanner = AuthScanner()
        self.integrity_scanner = IntegrityScanner()

    def check_sql_injection(self, url, enable_active_checks: bool = False):
        return self.sql_scanner.scan(url, enable_active_checks=enable_active_checks)

    def check_ssl(self, url):
        return self.ssl_scanner.check(url)

    def check_headers(self, url):
        return self.header_scanner.check(url)

    def check_zap(self, url, enable_active_checks: bool = False):
        return self.zap_scanner.scan(url, enable_active_checks=enable_active_checks)

    def check_nikto(self, url, enable_active_checks: bool = False):
        return self.nikto_scanner.scan(url, enable_active_checks=enable_active_checks)

    def check_wordpress(self, url, enable_active_checks: bool = False):
        return self.wordpress_scanner.check(url, enable_active_checks=enable_active_checks)

    def check_xss(self, url):
        return self.xss_scanner.scan(url)

    def check_tech(self, url):
        return self.tech_scanner.scan(url)

    def check_exposure(self, url, enable_active_checks: bool = False):
        return self.exposure_scanner.scan(url, enable_active_checks=enable_active_checks)

    def check_secrets(self, url):
        return self.secret_scanner.scan(url)

    def check_dns(self, url):
        return self.dns_scanner.check(url)

    def check_redirect(self, url):
        return self.redirect_scanner.scan(url)

    def check_takeover(self, url):
        return self.takeover_scanner.scan(url)

    def check_accessibility(self, url, page_paths=None):
        return self.accessibility_scanner.scan(url, page_paths=page_paths)

    def check_responsive_ux(self, url, page_paths=None):
        return self.responsive_scanner.scan(url, page_paths=page_paths)

    def check_performance_ux(self, url, page_paths=None):
        return self.performance_ux_scanner.scan(url, page_paths=page_paths)

    def check_form_usability(self, url, page_paths=None):
        return self.form_usability_scanner.scan(url, page_paths=page_paths)

    def check_seo(self, url, page_paths=None, page_type=None):
        return self.seo_scanner.scan(url, page_paths=page_paths, page_type=page_type)

    def check_visual_ai(self, url, page_paths=None, enabled=False, page_type=None):
        return self.visual_ai_scanner.scan(url, page_paths=page_paths, enabled=enabled, page_type=page_type)

    def check_abuse_controls(self, url, endpoints=None, budget=None, enabled=False):
        return self.abuse_controls_scanner.scan(url, endpoints=endpoints, budget=budget, enabled=enabled)

    def check_broken_links(self, url, page_paths=None):
        return self.broken_link_scanner.scan(url, page_paths=page_paths)

    def check_app_controls(
        self,
        url,
        page_paths=None,
        active_check_paths=None,
        auth_test_accounts=None,
        protected_paths=None,
        idor_paths=None,
    ):
        return self.app_controls_scanner.scan(
            url,
            page_paths=page_paths,
            active_check_paths=active_check_paths,
            auth_test_accounts=auth_test_accounts,
            protected_paths=protected_paths,
            idor_paths=idor_paths,
        )

    def check_exposed_services(self, url):
        return self.exposed_services_scanner.scan(url)

    def check_malware_analysis(self, url):
        return self.malware_scanner.scan(url)

    def check_ssrf(self, url, enable_active_checks: bool = False):
        return self.ssrf_scanner.scan(url, enable_active_checks=enable_active_checks)

    def check_logging_monitor(self, url):
        return self.logging_monitor_scanner.scan(url)

    def check_auth(self, url):
        return self.auth_scanner.scan(url)

    def check_integrity(self, url):
        return self.integrity_scanner.scan(url)

    def capture_screenshots(self, url):
        return self.screenshot_scanner.scan(url)

    def check_ai(self, url):
        if self.ai_scanner is None:
            self.ai_scanner = AI_Scanner()
        return self.ai_scanner.model_predict(url)
