import tldextract
import re
import logging
from ipwhois import IPWhois
import socket
import dns.resolver
from urllib.parse import urlparse
import threading
import time
import requests_cache
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.settings import settings

class EnhancedMaliciousDetector:
    def __init__(self):
        self.phishing_db_url = settings.phishing_db_url
        self.phishing_domains = set()
        self.last_db_update = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.http = requests_cache.CachedSession(
            cache_name=f"{settings.requests_cache_name}_intel",
            backend="sqlite",
            expire_after=settings.requests_cache_ttl_seconds,
            allowable_methods=("GET", "HEAD"),
            stale_if_error=True,
        )
        self.http.headers.update({"User-Agent": "WVS-MaliciousDetector/1.0"})
        
        # Additional malicious domain lists
        self.additional_lists = [
            'https://urlhaus.abuse.ch/downloads/text/',
            'https://openphish.com/feed.txt'
        ]
        
        # Cache for faster lookups
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.cache_timeout = 3600  # 1 hour cache validity
        
        # IP reputation lists. These can produce noisy results on shared hosting,
        # so they should be treated as weak signals unless corroborated.
        self.ip_dnsbl_services = [
            'zen.spamhaus.org',
            'dnsbl.sorbs.net',
            'bl.spamcop.net',
        ]

        # Domain blacklists. These should be queried using the domain name, not a reversed IP.
        self.domain_dnsbl_services = [
            'dbl.spamhaus.org',
            'multi.surbl.org',
        ]
        
        # Start background thread for DB updates
        threading.Thread(target=self.update_phishing_db, daemon=True).start()

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        reraise=True,
    )
    def _get(self, url, timeout=10):
        return self.http.get(url, timeout=timeout)

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        reraise=True,
    )
    def _head(self, url, timeout=5):
        return self.http.head(url, allow_redirects=True, timeout=timeout)

    def update_phishing_db(self):
        """Update phishing database"""
        try:
            # Main phishing database
            response = self._get(self.phishing_db_url, timeout=10)
            if response.status_code == 200:
                domains = set()
                for line in response.text.splitlines():
                    line = line.strip().lower()
                    if line:
                        domains.add(line)
                
                # Additional lists
                for url in self.additional_lists:
                    try:
                        resp = self._get(url, timeout=10)
                        if resp.status_code == 200:
                            for line in resp.text.splitlines():
                                line = line.strip().lower()
                                if line and not line.startswith('#'):
                                    # Extract domain from potential URLs
                                    parsed = urlparse(line if '://' in line else f'http://{line}')
                                    if parsed.netloc:
                                        domains.add(parsed.netloc)
                    except Exception as e:
                        logging.error(f"Failed to update additional list {url}: {str(e)}")
                
                with self.cache_lock:
                    self.phishing_domains = domains
                    self.cache = {}  # Clear cache on update
                
                logging.info(f"Updated phishing database with {len(self.phishing_domains)} entries")
                self.last_db_update = time.time()
                
                # Sleep for 6 hours before next update
                time.sleep(6 * 3600)
                return True
        except Exception as e:
            logging.error(f"Failed to update phishing database: {str(e)}")
            # Sleep for 10 minutes before retry on error
            time.sleep(10 * 60)
        return False

    def check_dnsbl(self, domain, full_domain=None):
        """Check target against IP and domain reputation lists."""
        try:
            # Use cache if available
            fqdn = (full_domain or domain or "").strip().lower()
            base_domain = (domain or "").strip().lower()
            cache_key = f"dnsbl:{base_domain}:{fqdn}"
            with self.cache_lock:
                if cache_key in self.cache:
                    cache_entry = self.cache[cache_key]
                    if time.time() - cache_entry['timestamp'] < self.cache_timeout:
                        return cache_entry['data']
            
            # Get IP address for the domain
            try:
                ip_address = socket.gethostbyname(domain)
            except socket.gaierror:
                ip_address = None

            detected_by = {}
            ip_hits = {}
            domain_hits = {}

            # Check IP blacklists
            if ip_address:
                reversed_ip = '.'.join(reversed(ip_address.split('.')))
                for dnsbl in self.ip_dnsbl_services:
                    try:
                        query = f"{reversed_ip}.{dnsbl}"
                        try:
                            self.resolver.resolve(query, 'A')
                            ip_hits[dnsbl] = "Listed"
                            detected_by[dnsbl] = "Listed"
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            continue
                        except dns.resolver.Timeout:
                            continue
                    except Exception:
                        continue

            # Check domain blacklists against the full host first, then the registered domain.
            domains_to_check = []
            if fqdn:
                domains_to_check.append(fqdn)
            if base_domain and base_domain not in domains_to_check:
                domains_to_check.append(base_domain)

            for candidate in domains_to_check:
                for dnsbl in self.domain_dnsbl_services:
                    try:
                        query = f"{candidate}.{dnsbl}"
                        try:
                            self.resolver.resolve(query, 'A')
                            domain_hits[dnsbl] = candidate
                            detected_by[dnsbl] = f"Listed for {candidate}"
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            continue
                        except dns.resolver.Timeout:
                            continue
                    except Exception:
                        continue

            # Get additional info about the IP
            network_info = {}
            if ip_address:
                try:
                    ipwhois = IPWhois(ip_address)
                    whois_result = ipwhois.lookup_whois()
                    network_info = {
                        'asn_description': whois_result.get('asn_description', ''),
                        'country': whois_result.get('asn_country_code', '')
                    }
                except Exception:
                    network_info = {}

            result = {
                'detected': detected_by,
                'ip_hits': ip_hits,
                'domain_hits': domain_hits,
                'total_checks': len(self.ip_dnsbl_services) + len(self.domain_dnsbl_services),
                'total_detected': len(detected_by),
                'ip_blacklisted': len(ip_hits) > 0,
                'domain_blacklisted': len(domain_hits) > 0,
                'blacklisted': len(detected_by) > 0,
                'ip_address': ip_address,
                'network_info': network_info
            }
            
            # Cache the result
            with self.cache_lock:
                self.cache[cache_key] = {
                    'timestamp': time.time(),
                    'data': result
                }
                
            return result
        except Exception as e:
            logging.error(f"DNSBL check error for {domain}: {str(e)}")
            return {'error': str(e), 'blacklisted': False}

    def is_phishing_domain(self, domain):
        """Check if domain matches any known phishing patterns"""
        if not domain:
            return False
            
        domain = domain.lower()
        
        # Use cache if available
        cache_key = f"phishing:{domain}"
        with self.cache_lock:
            if cache_key in self.cache:
                cache_entry = self.cache[cache_key]
                if time.time() - cache_entry['timestamp'] < self.cache_timeout:
                    return cache_entry['data']
        
        # Direct match
        result = domain in self.phishing_domains
        
        # Check for subdomain matches
        if not result:
            domain_parts = domain.split('.')
            for i in range(len(domain_parts) - 1):
                parent_domain = '.'.join(domain_parts[i:])
                if parent_domain in self.phishing_domains:
                    result = True
                    break
        
        # Cache the result
        with self.cache_lock:
            self.cache[cache_key] = {
                'timestamp': time.time(),
                'data': result
            }
            
        return result
        
    def check_redirects(self, url):
        """Check if URL redirects to suspicious domains"""
        try:
            response = self._head(url, timeout=5)
            if response.url != url:
                final_domain = urlparse(response.url).netloc
                original_domain = urlparse(url).netloc
                
                if final_domain != original_domain:
                    # Check if redirect target is in phishing database
                    if self.is_phishing_domain(final_domain):
                        return True, final_domain
            return False, None
        except Exception:
            return False, None

    def analyze_url(self, url):
        try:
            # Use cache if available
            cache_key = f"analysis:{url}"
            with self.cache_lock:
                if cache_key in self.cache:
                    cache_entry = self.cache[cache_key]
                    if time.time() - cache_entry['timestamp'] < self.cache_timeout:
                        return cache_entry['data']
        
            extracted = tldextract.extract(url)
            domain = extracted.registered_domain or url
            full_domain = extracted.fqdn or domain
            
            score = 0
            score_reasons = []
            
            # URL structure checks
            if len(url) > 90:
                score += 2
                score_reasons.append("Unusually long URL")
                
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                score += 3
                score_reasons.append("Contains IP address")
                
            if '@' in url:
                score += 3
                score_reasons.append("Contains @ symbol")
                
            if url.count('-') > 4:
                score += 1
                score_reasons.append("Excessive hyphens")
                
            if re.search(r'(\w+\.){4,}', url):
                score += 2
                score_reasons.append("Excessive subdomains")
                
            # Check for URL shorteners
            shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']
            if any(s in domain for s in shortener_domains):
                score += 2
                score_reasons.append("Uses URL shortener")
            
            # Check for suspicious keywords in domain
            suspicious_keywords = ['secure', 'account', 'banking', 'login', 'verify', 'signin', 'log-in']
            if any(keyword in domain.lower() for keyword in suspicious_keywords):
                score += 1
                score_reasons.append("Contains suspicious keywords")
            
            # Check phishing database
            phishing_match = (
                self.is_phishing_domain(full_domain) or 
                self.is_phishing_domain(domain)
            )
            
            if phishing_match:
                score += 5
                score_reasons.append("Domain in phishing database")
            
            # Check DNS blacklists
            dnsbl_result = self.check_dnsbl(domain, full_domain)
            if dnsbl_result.get('blacklisted', False):
                ip_detected = len(dnsbl_result.get('ip_hits', {}))
                domain_detected = len(dnsbl_result.get('domain_hits', {}))

                if domain_detected:
                    score += min(domain_detected * 4, 8)
                    score_reasons.append(
                        f"Listed in {domain_detected} domain blacklist{'s' if domain_detected != 1 else ''}"
                    )

                if ip_detected:
                    score += min(ip_detected, 2)
                    score_reasons.append(
                        f"Hosted on IP listed in {ip_detected} blacklist{'s' if ip_detected != 1 else ''}"
                    )

            # Check for redirects to suspicious domains
            redirect_check, redirect_domain = self.check_redirects(url)
            if redirect_check:
                score += 3
                score_reasons.append(f"Redirects to suspicious domain: {redirect_domain}")

            is_malicious = (
                phishing_match or
                dnsbl_result.get('domain_blacklisted', False) or
                score >= 5
            )

            result = {
                'score': score,
                'score_reasons': score_reasons,
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
            
            # Cache the result
            with self.cache_lock:
                self.cache[cache_key] = {
                    'timestamp': time.time(),
                    'data': result
                }
                
            return result
        except Exception as e:
            logging.error(f"Error analyzing URL {url}: {str(e)}")
            return {
                'score': 0,
                'score_reasons': ["Error analyzing URL"],
                'dnsbl': {'error': str(e), 'blacklisted': False},
                'phishing_match': False,
                'is_malicious': False,
                'domain_info': {'error': str(e)}
            }
