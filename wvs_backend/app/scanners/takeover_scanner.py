from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import dns.exception
import httpx

# CNAME targets that indicate a service is unclaimed.
# Format: (cname_suffix, http_fingerprint_pattern, service_name)
# http_fingerprint_pattern is matched case-insensitively in the response body
# when the CNAME target resolves but returns an error page.
_VULNERABLE_SERVICES: list[tuple[str, str, str]] = [
    # Static hosting / CDN
    ("github.io",              "There isn't a GitHub Pages site here",  "GitHub Pages"),
    ("githubusercontent.com",  "There isn't a GitHub Pages site here",  "GitHub Pages"),
    ("bitbucket.io",           "Repository not found",                  "Bitbucket Pages"),
    ("gitlab.io",              "404",                                    "GitLab Pages"),
    # PaaS / serverless
    ("herokuapp.com",          "No such app",                           "Heroku"),
    ("herokudns.com",          "No such app",                           "Heroku"),
    ("azurewebsites.net",      "404 Web Site not Found",                "Azure App Service"),
    ("cloudapp.azure.com",     "404 Web Site not Found",                "Azure Cloud App"),
    ("trafficmanager.net",     "404 Web Site not Found",                "Azure Traffic Manager"),
    ("blob.core.windows.net",  "BlobNotFound",                          "Azure Blob Storage"),
    ("cloudfront.net",         "ERROR: The request could not be satisfied", "AWS CloudFront"),
    ("s3.amazonaws.com",       "NoSuchBucket",                          "AWS S3"),
    ("s3-website",             "NoSuchBucket",                          "AWS S3 Website"),
    # SaaS
    ("shopify.com",            "Sorry, this shop is currently unavailable", "Shopify"),
    ("myshopify.com",          "Sorry, this shop is currently unavailable", "Shopify"),
    ("zendesk.com",            "Help Center Closed",                    "Zendesk"),
    ("statuspage.io",          "You are being redirected",              "Statuspage"),
    ("freshdesk.com",          "There is no helpdesk here",             "Freshdesk"),
    ("helpscoutdocs.com",      "No settings were found",                "HelpScout Docs"),
    ("cargo.site",             "If you're moving your domain",          "Cargo"),
    ("cargocollective.com",    "If you're moving your domain",          "Cargo Collective"),
    ("webflow.io",             "The page you are looking for doesn",    "Webflow"),
    ("hubspot.com",            "Domain not found",                      "HubSpot"),
    ("hubspotpagebuilder.com", "Domain not found",                      "HubSpot"),
    ("surge.sh",               "project not found",                     "Surge.sh"),
    ("netlify.app",            "Not Found - Request ID",                "Netlify"),
    ("netlify.com",            "Not Found - Request ID",                "Netlify"),
    ("readme.io",              "Project doesnt exist",                  "Readme.io"),
    ("ghost.io",               "Site not found",                        "Ghost"),
    ("fastly.com",             "Fastly error: unknown domain",          "Fastly"),
    ("wpengine.com",           "The site you were looking for",         "WP Engine"),
    ("kinsta.com",             "No site found",                         "Kinsta"),
    ("fly.dev",                "404 Not Found",                         "Fly.io"),
    ("render.com",             "not found on Render",                   "Render"),
    ("vercel.app",             "The deployment could not be found",     "Vercel"),
    ("pages.dev",              "Cloudflare Pages",                      "Cloudflare Pages"),
    ("workers.dev",            "1101",                                   "Cloudflare Workers"),
]

_NXDOMAIN_TAKEOVER_SERVICES: list[tuple[str, str]] = [
    # CNAME points to a hostname that no longer exists (NXDOMAIN) — classic takeover
    ("amazonaws.com",  "AWS S3 / Elastic Beanstalk"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    ("azure-api.net",  "Azure API Management"),
]


class SubdomainTakeoverScanner:
    def __init__(self, timeout: int = 8):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout
        self.http = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "WVS-TakeoverScanner/1.0"},
        )

    def _get_cname_chain(self, hostname: str) -> list[str]:
        chain: list[str] = []
        target = hostname
        for _ in range(10):
            try:
                answers = self.resolver.resolve(target, "CNAME")
                cname = answers[0].to_text().rstrip(".")
                chain.append(cname)
                target = cname
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                break
        return chain

    def _resolves(self, hostname: str) -> bool:
        try:
            socket.getaddrinfo(hostname, None)
            return True
        except socket.gaierror:
            return False

    def _http_fingerprint(self, url: str, pattern: str) -> bool:
        try:
            resp = self.http.get(url)
            return pattern.lower() in resp.text.lower()
        except Exception:
            return False

    def _check_dangling_cname(self, hostname: str, issues: list, recs: list) -> None:
        cname_chain = self._get_cname_chain(hostname)
        if not cname_chain:
            return

        final_cname = cname_chain[-1]

        # Check NXDOMAIN — final CNAME target doesn't exist at all
        if not self._resolves(final_cname):
            for suffix, service in _NXDOMAIN_TAKEOVER_SERVICES:
                if suffix in final_cname:
                    issues.append({
                        "name": f"Subdomain takeover risk — dangling CNAME to {service}",
                        "severity": "High",
                        "evidence": f"{hostname} CNAME chain ends at {final_cname} which does not resolve. "
                                    f"An attacker could register this resource on {service} and serve content under {hostname}.",
                    })
                    recs.append(f"Remove or update the dangling CNAME for {hostname} pointing to {final_cname}.")
                    return
            # Generic dangling CNAME even without a known service fingerprint
            issues.append({
                "name": "Dangling CNAME — target hostname does not resolve",
                "severity": "High",
                "evidence": f"{hostname} CNAME chain ends at {final_cname} which returned NXDOMAIN.",
            })
            recs.append(f"Remove the CNAME record for {hostname} or point it to an active resource.")
            return

        # Resolves but may show an unclaimed project page
        for suffix, fingerprint, service in _VULNERABLE_SERVICES:
            if suffix in final_cname:
                url_to_probe = f"https://{hostname}"
                if self._http_fingerprint(url_to_probe, fingerprint):
                    issues.append({
                        "name": f"Subdomain takeover — unclaimed {service} project",
                        "severity": "High",
                        "evidence": f"{hostname} CNAMEs to {final_cname} ({service}), "
                                    f"and the response contains the unclaimed-project fingerprint: '{fingerprint}'.",
                    })
                    recs.append(f"Claim the {service} project for {final_cname}, or remove the CNAME record for {hostname}.")
                break

    def _get_subdomains_from_dns(self, domain: str) -> list[str]:
        common = [
            "www", "mail", "email", "smtp", "pop", "imap", "ftp", "sftp",
            "dev", "staging", "stage", "test", "demo", "beta", "alpha",
            "api", "api2", "cdn", "static", "assets", "media", "img",
            "blog", "docs", "help", "support", "status", "portal", "app",
            "admin", "dashboard", "m", "mobile", "shop", "store",
            "vpn", "remote", "gateway", "proxy", "ns1", "ns2",
            "old", "legacy", "backup", "preview", "uat",
        ]
        found: list[str] = []
        for sub in common:
            fqdn = f"{sub}.{domain}"
            try:
                self.resolver.resolve(fqdn, "A")
                found.append(fqdn)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
        return found

    def scan(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        domain = hostname.lstrip("www.")

        issues: list[dict] = []
        recs: list[str] = []

        # Check the primary hostname
        self._check_dangling_cname(hostname, issues, recs)

        # Enumerate and check subdomains
        subdomains = self._get_subdomains_from_dns(domain)
        for sub in subdomains:
            if sub != hostname:
                self._check_dangling_cname(sub, issues, recs)

        seen: set[str] = set()
        deduped_recs = [r for r in recs if not (r in seen or seen.add(r))]

        score = max(0, 100 - (len(issues) * 20))

        return {
            "status": "issues_found" if issues else "ok",
            "domain": domain,
            "subdomains_checked": [hostname] + subdomains,
            "issues": issues,
            "recommendations": deduped_recs,
            "score": score,
        }

    def close(self):
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
