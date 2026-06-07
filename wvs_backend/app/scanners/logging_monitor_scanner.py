from __future__ import annotations

import uuid
from urllib.parse import urlparse, urljoin

import httpx
from bs4 import BeautifulSoup

_LOG_PATHS = ["/error.log", "/access.log", "/debug.log", "/app.log", "/application.log", "/server.log"]
_SECURITY_TXT_PATHS = ["/.well-known/security.txt", "/security.txt"]

_STACK_TRACE_MARKERS = [
    "traceback", "exception in", "fatal error:", "at line", "nullpointerexception",
    "system.exception", "org.springframework", "stack trace", "django.core",
    "flask.exceptions", "syntaxerror", "runtimeerror",
]

_MONITORING_DOMAINS = [
    "sentry.io", "sentry-cdn", "datadoghq", "newrelic.com",
    "rollbar.com", "bugsnag.com", "logrocket.com", "fullstory.com",
    "heap.io", "bugsnag",
]


class LoggingMonitorScanner:
    def __init__(self, timeout: int = 8):
        self._timeout = timeout

    def scan(self, url: str) -> dict:
        issues: list[dict] = []
        origin = _origin(url)

        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            self._check_security_txt(client, origin, issues)
            self._check_exposed_logs(client, origin, issues)
            self._check_verbose_errors(client, origin, issues)
            self._check_monitoring_sdk(client, url, issues)

        penalty = sum({"high": 20, "medium": 12, "low": 5}.get(i["severity"], 0) for i in issues)
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "score": max(0, 100 - penalty),
            "recommendations": [
                "Add a security.txt contact file at /.well-known/security.txt.",
                "Ensure log files are not publicly accessible.",
                "Configure error handlers to show generic messages in production.",
                "Integrate an error monitoring SDK (e.g. Sentry) for real-time alerting.",
            ] if issues else [],
        }

    def _check_security_txt(self, client: httpx.Client, origin: str, issues: list) -> None:
        found = False
        for path in _SECURITY_TXT_PATHS:
            try:
                r = client.get(origin + path)
                if r.status_code == 200 and r.text.strip():
                    found = True
                    break
            except Exception:
                pass
        if not found:
            issues.append({
                "title": "No security.txt contact file found",
                "severity": "low",
                "evidence": "Neither /.well-known/security.txt nor /security.txt returned a valid response.",
                "url": origin + "/.well-known/security.txt",
                "user_impact": "Security researchers cannot report vulnerabilities through an official channel.",
                "technical_remediation": "Create a security.txt file at /.well-known/security.txt per RFC 9116.",
                "owasp_category": "A09:2021 – Security Logging and Monitoring Failures",
            })

    def _check_exposed_logs(self, client: httpx.Client, origin: str, issues: list) -> None:
        for path in _LOG_PATHS:
            try:
                r = client.get(origin + path)
                content_type = r.headers.get("content-type", "")
                if r.status_code == 200 and r.content and ("text/" in content_type or len(r.content) > 100):
                    issues.append({
                        "title": f"Log file publicly accessible: {path}",
                        "severity": "high",
                        "evidence": f"GET {path} returned HTTP 200 ({len(r.content)} bytes).",
                        "content_preview": r.text[:2000].strip(),
                        "content_length": len(r.content),
                        "url": origin + path,
                        "user_impact": "Exposed logs can leak credentials, internal IP addresses, stack traces, and user data.",
                        "technical_remediation": "Block public access to log files via server configuration or move them outside the web root.",
                        "owasp_category": "A09:2021 – Security Logging and Monitoring Failures",
                    })
            except Exception:
                pass

    def _check_verbose_errors(self, client: httpx.Client, origin: str, issues: list) -> None:
        probe_path = f"/does-not-exist-{uuid.uuid4().hex[:8]}"
        try:
            r = client.get(origin + probe_path)
            body_lower = r.text.lower()
            matched = [m for m in _STACK_TRACE_MARKERS if m in body_lower]
            if matched:
                issues.append({
                    "title": "Verbose error disclosure detected",
                    "severity": "medium",
                    "evidence": f"Response to {probe_path} contains error markers: {', '.join(matched[:3])}",
                    "url": origin + probe_path,
                    "user_impact": "Stack traces expose framework internals, file paths, and code structure to attackers.",
                    "technical_remediation": "Configure production error handlers to display generic error messages and log details server-side only.",
                    "owasp_category": "A09:2021 – Security Logging and Monitoring Failures",
                })
        except Exception:
            pass

    def _check_monitoring_sdk(self, client: httpx.Client, url: str, issues: list) -> None:
        try:
            r = client.get(url)
            soup = BeautifulSoup(r.text, "html.parser")
            scripts = [tag.get("src", "") for tag in soup.find_all("script", src=True)]
            inline = r.text.lower()

            found = any(
                domain in (src or "").lower() or domain in inline
                for src in scripts
                for domain in _MONITORING_DOMAINS
            )

            if not found:
                issues.append({
                    "title": "No client-side error monitoring SDK detected",
                    "severity": "low",
                    "evidence": "No known monitoring SDK domains found in page scripts.",
                    "url": url,
                    "user_impact": "Without monitoring, security incidents and errors may go undetected until users report them.",
                    "technical_remediation": "Integrate an error monitoring tool such as Sentry, Datadog, or Rollbar to detect anomalies in real time.",
                    "owasp_category": "A09:2021 – Security Logging and Monitoring Failures",
                })
        except Exception:
            pass


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
