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
            
            # Convert Provider objects to serializable format and only include actual detections
            detected_by = {}
            for provider in result.detected_by:
                provider_str = str(provider)
                # Find the provider in the providers list
                for p in result.providers:
                    if str(p) == provider_str and p.response != 'unknown':
                        detected_by[provider_str] = str(p.response)

            return {
                'detected': detected_by,
                'total_checks': len(result.providers),
                'total_detected': len(detected_by)
            }
        except socket.gaierror:
            return {'error': 'Unable to resolve domain to IP'}

    def check_phishing_db(self, domain):
        try:
            response = requests.get(self.phishing_db_url)
            phishing_domains = set(response.text.splitlines())
            return domain in phishing_domains
        except requests.RequestException:
            return False

    def analyze_url(self, url):
        extracted = tldextract.extract(url)
        domain = extracted.registered_domain or url
        
        score = 0
        if len(url) > 90: score += 2
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): score += 3
        if '@' in url: score += 3
        if '-' in extracted.domain: score += 1
        
        dnsbl_result = self.check_dnsbl(domain)
        phishing_match = self.check_phishing_db(domain)
        
        is_malicious = (
            score >= 7 or 
            dnsbl_result.get('total_detected', 0) > 0 or 
            phishing_match
        )
        
        return {
            'score': score,
            'dnsbl': dnsbl_result,
            'phishing_match': bool(phishing_match),
            'is_malicious': is_malicious,
            'domain_info': {
                'registered_domain': extracted.registered_domain,
                'subdomain': extracted.subdomain,
                'tld': extracted.suffix
            }
        }
        
        
if __name__ == "__main__":
    detector = EnhancedMaliciousDetector()
    test_urls = [
        "http://google.com",
        "0001home.webflow.io",
    ]
    
    for url in test_urls:
        print(f"\nAnalyzing {url}:")
        result = detector.analyze_url(url)
        print(result)
        
        if result['is_malicious']:
            print("WARNING: Malicious URL detected!")
        else:
            print("URL is safe")
            