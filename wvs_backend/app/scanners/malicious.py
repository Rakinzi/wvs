import tldextract
import re
import requests
from pydnsbl import DNSBLIpChecker
import socket

class EnhancedMaliciousDetector:
    def __init__(self):
        self.dnsbl_checker = DNSBLIpChecker()
        self.phishing_db_url = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt'

    def check_dnsbl(self, domain):
        try:
            ip_address = socket.gethostbyname(domain)  
            result = self.dnsbl_checker.check(ip_address) 
            return {
                'detected': result.detected_by,
                'providers': result.providers,
                'total_checks': len(result.providers)
            }
        except socket.gaierror:
            return {'error': 'Unable to resolve domain to IP'}

    def check_phishing_db(self, domain):
        try:
            response = requests.get(self.phishing_db_url)
            phishing_domains = set(response.text.splitlines())  # Convert to a set for exact matching
            return domain in phishing_domains  # Check exact match
        except requests.RequestException:
            return False

    def analyze_url(self, url):
        extracted = tldextract.extract(url)
        domain = extracted.registered_domain
        
        score = 0
        if len(url) > 90: score += 2
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): score += 3
        if '@' in url: score += 3
        if '-' in extracted.domain: score += 1
        
        dnsbl_result = self.check_dnsbl(domain)
        phishing_match = self.check_phishing_db(domain)
        
        return {
            'score': score,
            'dnsbl': dnsbl_result,
            'phishing_match': phishing_match,
            'is_malicious': score >= 7 or dnsbl_result['detected'] or phishing_match,
            'domain_info': {
                'registered_domain': extracted.registered_domain,
                'subdomain': extracted.subdomain,
                'tld': extracted.suffix
            }
        }