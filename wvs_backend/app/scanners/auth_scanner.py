from __future__ import annotations

from urllib.parse import urlparse, urljoin

import httpx
from bs4 import BeautifulSoup

_AUTH_PATHS = ["/login", "/signin", "/sign-in", "/auth", "/api/login", "/api/auth"]
_SESSION_COOKIE_NAMES = {"session", "token", "auth", "jwt", "sid", "access_token", "refresh_token"}
_MFA_TERMS = [
    "two-factor", "2fa", "mfa", "multi-factor", "authenticator",
    "one-time", "otp", "verification code", "totp",
]


class AuthScanner:
    def __init__(self, timeout: int = 8):
        self._timeout = timeout

    def scan(self, url: str) -> dict:
        issues: list[dict] = []
        is_https = url.lower().startswith("https://")

        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                resp = client.get(url)
                self._check_password_autocomplete(resp, url, issues)
                self._check_cookie_flags(resp, url, is_https, issues)
                self._check_mfa_signal(resp, url, issues)

            self._check_auth_endpoint_rate_limiting(url, issues)

        except Exception:
            pass

        penalty = sum({"high": 15, "medium": 8, "low": 3}.get(i["severity"], 0) for i in issues)
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "score": max(0, 100 - penalty),
            "recommendations": [
                "Set HttpOnly, Secure, and SameSite=Lax on all session cookies.",
                "Implement rate limiting on authentication endpoints.",
                "Enable multi-factor authentication for user accounts.",
                "Add autocomplete attributes to password fields.",
            ] if issues else [],
        }

    def _check_password_autocomplete(self, resp: httpx.Response, url: str, issues: list) -> None:
        soup = BeautifulSoup(resp.text, "html.parser")
        for field in soup.find_all("input", type="password"):
            ac = (field.get("autocomplete") or "").lower()
            if ac not in {"new-password", "current-password", "off"}:
                issues.append({
                    "title": "Password field missing autocomplete attribute",
                    "severity": "low",
                    "evidence": f"<input type=\"password\"> element missing autocomplete on {url}",
                    "url": url,
                    "user_impact": "Browsers may auto-fill passwords in unintended contexts.",
                    "technical_remediation": "Add autocomplete=\"current-password\" or autocomplete=\"new-password\" to password inputs.",
                    "owasp_category": "A07:2021 – Identification and Authentication Failures",
                })
                break

    def _check_cookie_flags(self, resp: httpx.Response, url: str, is_https: bool, issues: list) -> None:
        seen: set[str] = set()
        for header_val in resp.headers.get_list("set-cookie"):
            parts = [p.strip().lower() for p in header_val.split(";")]
            name = parts[0].split("=")[0] if parts else ""
            if name in seen:
                continue
            seen.add(name)

            is_session_cookie = any(term in name for term in _SESSION_COOKIE_NAMES)

            if "httponly" not in parts:
                issues.append({
                    "title": f"Cookie '{name}' missing HttpOnly flag",
                    "severity": "medium",
                    "evidence": f"Set-Cookie header for '{name}' does not include HttpOnly.",
                    "url": url,
                    "user_impact": "Cookie is accessible via JavaScript, enabling session theft via XSS.",
                    "technical_remediation": "Set the HttpOnly flag on all session and authentication cookies.",
                    "owasp_category": "A07:2021 – Identification and Authentication Failures",
                })

            if is_https and "secure" not in parts:
                issues.append({
                    "title": f"Cookie '{name}' missing Secure flag",
                    "severity": "medium",
                    "evidence": f"Set-Cookie header for '{name}' does not include Secure on an HTTPS site.",
                    "url": url,
                    "user_impact": "Cookie can be transmitted over unencrypted HTTP connections.",
                    "technical_remediation": "Set the Secure flag on all cookies on HTTPS sites.",
                    "owasp_category": "A07:2021 – Identification and Authentication Failures",
                })

            if is_session_cookie and not any(p.startswith("samesite") for p in parts):
                issues.append({
                    "title": f"Session cookie '{name}' missing SameSite attribute",
                    "severity": "medium",
                    "evidence": f"Session cookie '{name}' has no SameSite attribute.",
                    "url": url,
                    "user_impact": "Cookie is vulnerable to cross-site request forgery (CSRF).",
                    "technical_remediation": "Set SameSite=Lax or SameSite=Strict on all session cookies.",
                    "owasp_category": "A07:2021 – Identification and Authentication Failures",
                })

    def _check_mfa_signal(self, resp: httpx.Response, url: str, issues: list) -> None:
        body_lower = resp.text.lower()
        if not any(term in body_lower for term in _MFA_TERMS):
            issues.append({
                "title": "No multi-factor authentication signal detected",
                "severity": "low",
                "evidence": "No MFA-related terms found in page content.",
                "url": url,
                "user_impact": "Without MFA, compromised passwords give attackers full account access.",
                "technical_remediation": "Implement TOTP-based or WebAuthn MFA for user accounts.",
                "owasp_category": "A07:2021 – Identification and Authentication Failures",
            })

    def _check_auth_endpoint_rate_limiting(self, url: str, issues: list) -> None:
        origin = _origin(url)
        for path in _AUTH_PATHS:
            try:
                with httpx.Client(timeout=5, follow_redirects=False) as client:
                    resp = client.head(origin + path)
                if resp.status_code in {200, 301, 302, 405}:
                    headers = {k.lower() for k in resp.headers}
                    has_ratelimit = any(h in headers for h in {
                        "x-ratelimit-limit", "x-rate-limit-limit",
                        "retry-after", "x-ratelimit-remaining",
                    })
                    if not has_ratelimit:
                        issues.append({
                            "title": f"No rate-limit headers on authentication endpoint {path}",
                            "severity": "medium",
                            "evidence": f"HEAD {origin + path} returned {resp.status_code} with no rate-limit headers.",
                            "url": origin + path,
                            "user_impact": "Authentication endpoints without rate limiting are vulnerable to credential stuffing and brute-force attacks.",
                            "technical_remediation": "Implement rate limiting on auth endpoints and return X-RateLimit-Limit / Retry-After headers.",
                            "owasp_category": "A07:2021 – Identification and Authentication Failures",
                        })
                    break
            except Exception:
                continue


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
