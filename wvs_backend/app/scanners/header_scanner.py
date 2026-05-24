from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests_cache
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.settings import settings

_SEVERITY_WEIGHT = {"High": 20, "Medium": 12, "Low": 5}

# Headers that must be present
_REQUIRED = {
    "content-security-policy":        ("High",   "Add a Content-Security-Policy header to defend against XSS."),
    "strict-transport-security":      ("Medium", "Enable HSTS to force browsers to use HTTPS."),
    "x-content-type-options":         ("Medium", "Set X-Content-Type-Options: nosniff to prevent MIME sniffing."),
    "x-frame-options":                ("Medium", "Set X-Frame-Options to DENY or SAMEORIGIN to block clickjacking."),
    "referrer-policy":                ("Low",    "Set Referrer-Policy to control how much referrer info is sent."),
    "permissions-policy":             ("Low",    "Add a Permissions-Policy header to restrict browser feature access."),
    "cross-origin-opener-policy":     ("Medium", "Add Cross-Origin-Opener-Policy: same-origin to prevent Spectre-style cross-origin attacks."),
    "cross-origin-resource-policy":   ("Low",    "Add Cross-Origin-Resource-Policy: same-origin to prevent cross-site resource loading."),
}

# Headers that must NOT be present (information disclosure)
_FORBIDDEN = {
    "x-powered-by":          ("Low", "Remove X-Powered-By — it discloses the server technology stack."),
    "server":                 ("Low", "Suppress or genericise the Server header to avoid version disclosure."),
    "x-aspnet-version":       ("Low", "Remove X-AspNet-Version to avoid disclosing the .NET runtime version."),
    "x-aspnetmvc-version":    ("Low", "Remove X-AspNetMvc-Version to avoid disclosing MVC version."),
    "x-runtime":              ("Low", "Remove X-Runtime — it discloses server response timing (Rails)."),
    "x-debug-token":          ("Low", "Remove X-Debug-Token — it can expose access to the Symfony profiler."),
    "x-debug-token-link":     ("Medium", "Remove X-Debug-Token-Link — it directly links to the Symfony profiler."),
    "x-application-context":  ("Low", "Remove X-Application-Context — it discloses the Spring Boot app context."),
    "x-generator":            ("Low", "Remove X-Generator — it discloses the CMS or framework in use."),
    "x-drupal-cache":         ("Low", "Remove X-Drupal-Cache — it confirms Drupal is in use, aiding targeted attacks."),
}

# CSP directives that indicate a dangerously weak policy
_UNSAFE_CSP = ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:"]


class HeaderScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests_cache.CachedSession(
            cache_name=f"{settings.requests_cache_name}_headers",
            backend="sqlite",
            expire_after=min(settings.requests_cache_ttl_seconds, 900),
            allowable_methods=("GET", "OPTIONS"),
        )
        self.session.headers.update({"User-Agent": "WVS-HeaderScanner/1.0"})

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        reraise=True,
    )
    def _get(self, url: str):
        return self.session.get(url, timeout=self.timeout, allow_redirects=True)

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=2),
        reraise=True,
    )
    def _options(self, url: str):
        return self.session.options(url, timeout=self.timeout, allow_redirects=True)

    def check(self, url: str) -> dict[str, Any]:
        is_https = urlparse(url).scheme == "https"
        result: dict[str, Any] = {
            "status": "ok",
            "https": is_https,
            "final_url": url,
            "redirect_chain": [],
            "present_headers": {},
            "issues": [],
            "recommendations": [],
            "score": 100,
        }

        try:
            response = self._get(url)
        except Exception as exc:
            return {
                "status": "error",
                "https": is_https,
                "issues": [{"name": "Header scan failed", "severity": "Medium", "evidence": str(exc)}],
                "recommendations": ["Confirm the target is reachable before running header checks."],
                "score": 0,
            }

        headers = {k.lower(): v for k, v in response.headers.items()}
        result["final_url"] = response.url
        result["redirect_chain"] = [r.url for r in response.history] + [response.url]
        result["present_headers"] = {k: headers[k] for k in _REQUIRED if k in headers}

        issues = result["issues"]
        recs = result["recommendations"]

        # HTTPS redirect check
        if is_https and not response.url.startswith("https://"):
            issues.append({
                "name": "HTTPS downgrade — missing HTTPS redirect",
                "severity": "High",
                "evidence": f"Request ended at {response.url}",
            })

        # X-XSS-Protection should be disabled (0), not set to 1 which re-enables a buggy browser feature
        xxp = headers.get("x-xss-protection", "")
        if xxp and xxp.strip() not in ("0", ""):
            issues.append({
                "name": "X-XSS-Protection should be set to 0",
                "severity": "Low",
                "evidence": f"Value: {xxp} — the legacy XSS filter causes its own vulnerabilities in old IE/Edge.",
            })
            recs.append("Set X-XSS-Protection: 0 (the CSP header is the correct defence).")

        # Required headers missing
        for header, (severity, rec) in _REQUIRED.items():
            if header not in headers:
                issues.append({
                    "name": f"Missing {header}",
                    "severity": severity,
                    "evidence": f"{header} was not present in the response.",
                })
                recs.append(rec)

        # HSTS value checks (only meaningful on HTTPS)
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            if "includesubdomains" not in hsts.lower():
                issues.append({
                    "name": "HSTS missing includeSubDomains",
                    "severity": "Low",
                    "evidence": f"Value: {hsts}",
                })
                recs.append("Add includeSubDomains to your HSTS header.")
            try:
                max_age = int(next(
                    p.split("=")[1] for p in hsts.split(";") if "max-age" in p.lower()
                ))
                if max_age < 31536000:
                    issues.append({
                        "name": "HSTS max-age too short",
                        "severity": "Low",
                        "evidence": f"max-age={max_age} (recommended: 31536000)",
                    })
                    recs.append("Set HSTS max-age to at least 31536000 (1 year).")
            except (StopIteration, ValueError, IndexError):
                pass

        # Information-disclosing headers that should be removed
        for header, (severity, rec) in _FORBIDDEN.items():
            val = headers.get(header)
            if val:
                issues.append({
                    "name": f"Information disclosure via {header}",
                    "severity": severity,
                    "evidence": f"{header}: {val}",
                })
                recs.append(rec)

        # Insecure cookies
        insecure = [c.name for c in response.cookies if not c.secure]
        if insecure:
            issues.append({
                "name": "Cookies missing Secure flag",
                "severity": "Medium",
                "evidence": ", ".join(insecure[:10]),
            })
            recs.append("Mark all session and sensitive cookies with the Secure attribute.")

        # HttpOnly cookies check
        httponly_missing = []
        samesite_missing = []
        for cookie in response.cookies:
            if not cookie.has_nonstandard_attr("HttpOnly"):
                httponly_missing.append(cookie.name)
            if not cookie.get_nonstandard_attr("SameSite"):
                samesite_missing.append(cookie.name)
        if httponly_missing:
            issues.append({
                "name": "Cookies missing HttpOnly flag",
                "severity": "Medium",
                "evidence": ", ".join(httponly_missing[:10]),
            })
            recs.append("Mark session cookies with HttpOnly to prevent JavaScript access.")
        if samesite_missing:
            issues.append({
                "name": "Cookies missing SameSite attribute",
                "severity": "Low",
                "evidence": ", ".join(samesite_missing[:10]),
            })
            recs.append("Set SameSite=Lax or SameSite=Strict on cookies unless cross-site use is required.")

        # CSP quality analysis
        csp = headers.get("content-security-policy", "")
        if csp:
            for unsafe in _UNSAFE_CSP:
                if unsafe in csp.lower():
                    issues.append({
                        "name": f"Weak CSP directive: {unsafe}",
                        "severity": "Medium",
                        "evidence": f"CSP contains '{unsafe}' which significantly weakens XSS protection.",
                    })
                    recs.append(f"Remove '{unsafe}' from your Content-Security-Policy.")
            if "*" in csp and "script-src" in csp.lower():
                issues.append({
                    "name": "CSP script-src wildcard",
                    "severity": "High",
                    "evidence": "Wildcard (*) in script-src allows scripts from any origin.",
                })
            if "object-src" not in csp.lower():
                issues.append({
                    "name": "CSP missing object-src",
                    "severity": "Low",
                    "evidence": "Add object-src 'none' to block Flash and other plugin execution.",
                })
            if "base-uri" not in csp.lower():
                issues.append({
                    "name": "CSP missing base-uri",
                    "severity": "Low",
                    "evidence": "Add base-uri 'self' to prevent base tag hijacking.",
                })

        # CORS misconfiguration
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            issues.append({
                "name": "CORS: wildcard with credentials",
                "severity": "High",
                "evidence": "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is forbidden by spec and exploitable.",
            })
            recs.append("Specify an explicit origin in Access-Control-Allow-Origin instead of * when credentials are allowed.")
        elif acao and acao != "*":
            # Reflect-origin CORS — flag if it just echoes back whatever origin was sent
            # We can't test this without sending a probe; note it as informational
            result["cors_origin"] = acao

        # Risky HTTP methods
        try:
            options_response = self._options(url)
            allow_header = options_response.headers.get("Allow", "")
            allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
            result["allowed_methods"] = allowed_methods
            risky_methods = [m for m in allowed_methods if m in {"TRACE", "CONNECT", "PUT", "DELETE"}]
            if risky_methods:
                issues.append({
                    "name": "Risky HTTP methods enabled",
                    "severity": "Medium",
                    "evidence": ", ".join(risky_methods),
                })
                recs.append("Disable unnecessary HTTP methods such as TRACE, CONNECT, PUT, and DELETE at the web server or reverse proxy.")
        except Exception:
            result["allowed_methods"] = []

        # HSTS preload directive
        if hsts and "preload" not in hsts.lower():
            issues.append({
                "name": "HSTS missing preload directive",
                "severity": "Low",
                "evidence": "Add 'preload' to HSTS and submit to the HSTS preload list for stronger protection.",
            })
            recs.append("Add the 'preload' directive to your HSTS header and submit to hstspreload.org.")

        # Deduplicate recs
        seen: set[str] = set()
        result["recommendations"] = [r for r in recs if not (r in seen or seen.add(r))]

        penalty = sum(_SEVERITY_WEIGHT.get(i["severity"], 5) for i in issues)
        result["score"] = max(0, 100 - penalty)
        result["status"] = "issues_found" if issues else "ok"
        return result
