from __future__ import annotations

import time
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx
from bs4 import BeautifulSoup

_SSRF_PARAMS = {
    "url", "redirect", "target", "next", "link", "src", "dest",
    "fetch", "proxy", "image", "uri", "path", "endpoint",
}

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://localhost/",
]

_IMDS_MARKERS = {"ami-id", "instance-id", "iam", "security-credentials", "meta-data"}
_RFC1918 = re.compile(r"\b(10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2\d\.\d+\.\d+|172\.3[01]\.\d+\.\d+|192\.168\.\d+\.\d+)\b")


class SSRFScanner:
    def __init__(self, timeout: int = 8):
        self._timeout = timeout
        self._probe_timeout = 3

    def scan(self, url: str, enable_active_checks: bool = False) -> dict:
        if not enable_active_checks:
            return {"status": "disabled", "issues": [], "score": 100, "params_tested": []}

        issues: list[dict] = []
        tested_pairs: list[str] = []

        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                resp = client.get(url)
                soup = BeautifulSoup(resp.text, "html.parser")

            origin = _origin(url)
            candidate_urls: set[str] = set()

            for tag in soup.find_all("a", href=True):
                href = str(tag["href"])
                if href.startswith("/") or href.startswith(origin):
                    candidate_urls.add(_absolute(href, origin))

            for tag in soup.find_all("form", action=True):
                action = str(tag["action"])
                candidate_urls.add(_absolute(action, origin))

            candidate_urls.add(url)

            for candidate in candidate_urls:
                parsed = urlparse(candidate)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                matching = {k: v for k, v in qs.items() if k.lower() in _SSRF_PARAMS}
                if not matching:
                    continue

                for param in matching:
                    pair = f"{candidate}|{param}"
                    if pair in tested_pairs:
                        continue
                    tested_pairs.append(pair)

                    issue = self._probe(candidate, parsed, qs, param)
                    if issue:
                        issues.append(issue)

        except Exception:
            pass

        penalty = sum({"critical": 30, "high": 20, "medium": 10}.get(i.get("severity", ""), 0) for i in issues)
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "score": max(0, 100 - penalty),
            "params_tested": tested_pairs,
            "recommendations": [
                "Validate and allowlist URL destinations server-side.",
                "Block requests to RFC-1918 ranges and cloud metadata services.",
                "Never pass user-supplied URLs to server-side fetch calls without strict validation.",
            ] if issues else [],
        }

    def _probe(self, candidate: str, parsed, qs: dict, param: str) -> dict | None:
        for payload in _SSRF_PAYLOADS:
            injected_qs = dict(qs)
            injected_qs[param] = [payload]
            new_query = urlencode(injected_qs, doseq=True)
            probe_url = urlunparse(parsed._replace(query=new_query))

            try:
                with httpx.Client(timeout=self._probe_timeout, follow_redirects=False) as client:
                    start = time.monotonic()
                    resp = client.get(probe_url)
                    elapsed = time.monotonic() - start

                body_lower = resp.text.lower()

                if any(marker in body_lower for marker in _IMDS_MARKERS):
                    return _issue("critical", param, probe_url, "Response body contains cloud instance metadata content.")

                if _RFC1918.search(resp.text):
                    return _issue("high", param, probe_url, "Response body contains RFC-1918 private IP address.")

                if "localhost" in payload and elapsed > self._probe_timeout * 0.9:
                    return _issue("medium", param, probe_url, f"Loopback SSRF probe took {elapsed:.1f}s — possible internal connection attempt.")

            except httpx.TimeoutException:
                if "localhost" in payload or "169.254" in payload:
                    return _issue("medium", param, probe_url, "SSRF probe timed out on internal target — possible connection attempt.")
            except Exception:
                pass

        return None


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _absolute(href: str, origin: str) -> str:
    if href.startswith("http://") or href.startswith("https://"):
        return href
    return origin + ("" if href.startswith("/") else "/") + href


def _issue(severity: str, param: str, probe_url: str, detail: str) -> dict:
    return {
        "title": f"Potential SSRF via parameter '{param}'",
        "severity": severity,
        "evidence": f"Parameter '{param}' on {probe_url[:120]}: {detail}",
        "url": probe_url,
        "user_impact": "SSRF can expose cloud metadata credentials, internal services, or enable lateral movement.",
        "technical_remediation": "Validate and allowlist URL destinations server-side. Block RFC-1918 ranges and metadata services.",
        "owasp_category": "A10:2021 – Server-Side Request Forgery",
        "standard_reference": "OWASP WSTG - SSRF (OTG-INPVAL-019)",
    }
