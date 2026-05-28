from __future__ import annotations

from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

_CICD_PATHS = [
    "/.travis.yml",
    "/Jenkinsfile",
    "/.circleci/config.yml",
    "/circle.yml",
    "/package-lock.json",
    "/yarn.lock",
    "/Pipfile.lock",
    "/composer.lock",
]


class IntegrityScanner:
    def __init__(self, timeout: int = 8):
        self._timeout = timeout

    def scan(self, url: str) -> dict:
        issues: list[dict] = []
        origin = _origin(url)

        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                resp = client.get(url)
                headers = resp.headers
                soup = BeautifulSoup(resp.text, "html.parser")

                self._check_external_scripts_sri(soup, origin, url, issues)
                self._check_external_stylesheets_sri(soup, origin, url, issues)
                self._check_csp(headers, url, issues)
                self._check_exposed_cicd(client, origin, issues)

        except Exception:
            pass

        penalty = sum({"high": 15, "medium": 8, "low": 3}.get(i["severity"], 0) for i in issues)
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "score": max(0, 100 - penalty),
            "recommendations": [
                "Add integrity= (SRI hash) and crossorigin= attributes to all external scripts and stylesheets.",
                "Implement a Content-Security-Policy header to enforce SRI.",
                "Block public access to CI/CD config files and dependency lockfiles.",
            ] if issues else [],
        }

    def _check_external_scripts_sri(self, soup: BeautifulSoup, origin: str, url: str, issues: list) -> None:
        seen: set[str] = set()
        for tag in soup.find_all("script", src=True):
            src = str(tag.get("src", ""))
            if not src or _is_same_origin(src, origin) or src in seen:
                continue
            seen.add(src)
            if not tag.get("integrity"):
                issues.append({
                    "title": "External script loaded without Subresource Integrity (SRI)",
                    "severity": "high",
                    "evidence": f"<script src=\"{src[:100]}\"> has no integrity attribute.",
                    "url": url,
                    "user_impact": "A compromised CDN could serve malicious JavaScript that executes in your users' browsers.",
                    "technical_remediation": f"Add integrity=\"sha256-<hash>\" crossorigin=\"anonymous\" to the script tag for {src[:80]}",
                    "owasp_category": "A08:2021 – Software and Data Integrity Failures",
                })

    def _check_external_stylesheets_sri(self, soup: BeautifulSoup, origin: str, url: str, issues: list) -> None:
        seen: set[str] = set()
        for tag in soup.find_all("link", rel=True):
            rels = [r.lower() for r in (tag.get("rel") or [])]
            if "stylesheet" not in rels:
                continue
            href = str(tag.get("href", ""))
            if not href or _is_same_origin(href, origin) or href in seen:
                continue
            seen.add(href)
            if not tag.get("integrity"):
                issues.append({
                    "title": "External stylesheet loaded without Subresource Integrity (SRI)",
                    "severity": "medium",
                    "evidence": f"<link rel=\"stylesheet\" href=\"{href[:100]}\"> has no integrity attribute.",
                    "url": url,
                    "user_impact": "A compromised CDN could inject malicious CSS to steal form data or deface the page.",
                    "technical_remediation": f"Add integrity=\"sha256-<hash>\" crossorigin=\"anonymous\" to the link tag for {href[:80]}",
                    "owasp_category": "A08:2021 – Software and Data Integrity Failures",
                })

    def _check_csp(self, headers: httpx.Headers, url: str, issues: list) -> None:
        if not headers.get("content-security-policy"):
            issues.append({
                "title": "Content-Security-Policy header missing — SRI enforcement weakened",
                "severity": "medium",
                "evidence": "No Content-Security-Policy header found. Without CSP, browsers cannot enforce SRI for subresources.",
                "url": url,
                "user_impact": "Missing CSP means SRI hashes are advisory only; attackers can still inject unauthorized scripts.",
                "technical_remediation": "Implement a Content-Security-Policy header that includes require-sri-for script style.",
                "owasp_category": "A08:2021 – Software and Data Integrity Failures",
            })

    def _check_exposed_cicd(self, client: httpx.Client, origin: str, issues: list) -> None:
        for path in _CICD_PATHS:
            try:
                r = client.get(origin + path)
                if r.status_code == 200 and r.content:
                    issues.append({
                        "title": f"CI/CD configuration or lockfile publicly accessible: {path}",
                        "severity": "low",
                        "evidence": f"GET {path} returned HTTP 200 ({len(r.content)} bytes).",
                        "url": origin + path,
                        "user_impact": "Exposed build configs and lockfiles reveal dependency trees, pipeline secrets, and deployment topology.",
                        "technical_remediation": f"Block public access to {path} via server configuration or move it outside the web root.",
                        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
                    })
            except Exception:
                pass


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _is_same_origin(src: str, origin: str) -> bool:
    if src.startswith("/"):
        return True
    try:
        return urlparse(src).netloc == urlparse(origin).netloc
    except Exception:
        return False
