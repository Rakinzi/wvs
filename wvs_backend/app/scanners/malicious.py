import tldextract
import re
import requests
import logging
from ipwhois import IPWhois
import socket
import dns.resolver

class EnhancedMaliciousDetector:
    def __init__(self):
        self.phishing_db_url = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt'
        self.phishing_domains = set()  # Initialize empty set
        self.last_db_update = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.update_phishing_db()  # Load database immediately
        
        # Common DNSBL services
        self.dnsbl_services = [
            'zen.spamhaus.org',
            'dnsbl.sorbs.net',
            'bl.spamcop.net'
        ]

    def update_phishing_db(self):
        """Update phishing database"""
        try:
            response = requests.get(self.phishing_db_url, timeout=10)
            if response.status_code == 200:
                domains = set()
                for line in response.text.splitlines():
                    line = line.strip().lower()
                    if line:
                        domains.add(line)
                        domains.add(f"www.{line}")
                        domains.add(f"*.{line}")
                
                self.phishing_domains = domains
                logging.info(f"Updated phishing database with {len(self.phishing_domains)} entries")
                return True
        except Exception as e:
            logging.error(f"Failed to update phishing database: {str(e)}")
        return False

    def check_dnsbl(self, domain):
        """Check domain against DNSBL services"""
        try:
            # Get IP address for the domain
            try:
                ip_address = socket.gethostbyname(domain)
            except socket.gaierror:
                return {'error': 'Cannot resolve domain', 'blacklisted': False}

            # Reverse the IP address for DNSBL lookup
            reversed_ip = '.'.join(reversed(ip_address.split('.')))
            detected_by = {}

            # Check each DNSBL service
            for dnsbl in self.dnsbl_services:
                try:
                    query = f"{reversed_ip}.{dnsbl}"
                    try:
                        self.resolver.resolve(query, 'A')
                        detected_by[dnsbl] = "Listed"
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        continue
                    except dns.resolver.Timeout:
                        continue
                except Exception:
                    continue

            # Get additional info about the IP
            try:
                ipwhois = IPWhois(ip_address)
                whois_result = ipwhois.lookup_whois()
                network_info = {
                    'asn_description': whois_result.get('asn_description', ''),
                    'country': whois_result.get('asn_country_code', '')
                }
            except Exception:
                network_info = {}

            return {
                'detected': detected_by,
                'total_checks': len(self.dnsbl_services),
                'total_detected': len(detected_by),
                'blacklisted': len(detected_by) > 0,
                'ip_address': ip_address,
                'network_info': network_info
            }
        except Exception as e:
            logging.error(f"DNSBL check error for {domain}: {str(e)}")
            return {'error': str(e), 'blacklisted': False}

    def is_phishing_domain(self, domain):
        """Check if domain matches any known phishing patterns"""
        if not domain:
            return False
            
        domain = domain.lower()
        
        if domain in self.phishing_domains:
            return True
            
        domain_parts = domain.split('.')
        for i in range(len(domain_parts)):
            wildcard_domain = f"*.{'.'.join(domain_parts[i:])}"
            if wildcard_domain in self.phishing_domains:
                return True
        
        return False

    def analyze_url(self, url):
        try:
            extracted = tldextract.extract(url)
            domain = extracted.registered_domain or url
            full_domain = extracted.fqdn or domain
            
            score = 0
            if len(url) > 90: score += 2
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): score += 3
            if '@' in url: score += 3
            if '-' in extracted.domain: score += 1
            
            phishing_match = (
                self.is_phishing_domain(full_domain) or 
                self.is_phishing_domain(domain)
            )
            
            if phishing_match:
                logging.info(f"Phishing match found for domain: {domain}")
            
            dnsbl_result = self.check_dnsbl(domain)
            
            is_malicious = (
                score >= 7 or
                dnsbl_result.get('blacklisted', False) or
                phishing_match
            )
            
            return {
                'score': score,
                'dnsbl': dnsbl_result,
                'phishing_match': phishing_match,
                'is_malicious': is_malicious,
                'domain_info': {
                    'registered_domain': extracted.registered_domain,
                    'full_domain': full_domain,
                    'subdomain': extracted.subdomain,
                    'tld': extracted.suffix
                }
            }
        except Exception as e:
            logging.error(f"Error analyzing URL {url}: {str(e)}")
            return {
                'score': 0,
                'dnsbl': {'error': str(e), 'blacklisted': False},
                'phishing_match': False,
                'is_malicious': True,
                'domain_info': {'error': str(e)}
            }