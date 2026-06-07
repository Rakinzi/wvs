from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from app.settings import settings
from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.ux_scan_helpers import build_page_targets, ux_finding_defaults


class AppControlsScanner:
    COMMON_API_SPECS = (
        "/openapi.json",
        "/swagger.json",
        "/api/openapi.json",
        "/api/swagger.json",
        "/api-docs",
        "/v3/api-docs",
        "/docs/openapi.json",
    )
    WEBHOOK_PATHS = (
        "/webhook",
        "/webhooks",
        "/api/webhook",
        "/api/webhooks",
        "/stripe/webhook",
        "/api/stripe/webhook",
        "/callback",
        "/callbacks",
        "/api/callback",
        "/api/callbacks",
    )
    UPLOAD_PATHS = (
        "/upload",
        "/uploads",
        "/api/upload",
        "/api/uploads",
        "/files/upload",
        "/api/files/upload",
    )
    AUTH_PATH_TERMS = (
        "/login",
        "/signin",
        "/sign-in",
        "/auth/login",
        "/api/login",
        "/api/auth/login",
        "/account",
        "/dashboard",
        "/admin",
    )
    ACCOUNT_CREATION_TERMS = (
        "signup",
        "sign up",
        "register",
        "create account",
        "/signup",
        "/sign-up",
        "/register",
        "/api/signup",
        "/api/register",
    )
    MFA_TERMS = ("mfa", "2fa", "two-factor", "one-time", "otp", "verification code", "authenticator")
    EMAIL_VERIFY_TERMS = ("verify your email", "email verification", "verification email", "confirm your email")
    ENDPOINT_RE = re.compile(
        r"""(?:"|')((?:https?://[^"']+)|(?:/api/[A-Za-z0-9_./?&=%:-]+)|(?:/[A-Za-z0-9_.-]+/[A-Za-z0-9_./?&=%:-]+))(?:"|')"""
    )

    def __init__(self, timeout_seconds: int | None = None):
        self.timeout = timeout_seconds or settings.app_controls_timeout_seconds
        self.timeout_ms = self.timeout * 1000

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _same_origin(self, base_url: str, candidate: str) -> bool:
        base = urlparse(base_url)
        parsed = urlparse(candidate)
        return base.scheme == parsed.scheme and base.netloc == parsed.netloc

    def _resolve_url(self, base_url: str, value: str) -> str | None:
        raw = str(value or "").strip()
        if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            return None
        candidate = urljoin(self._origin(base_url) + "/", raw)
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        return candidate if self._same_origin(base_url, candidate) else None

    def _issue(
        self,
        scanner: str,
        category: str,
        page_url: str,
        *,
        title: str,
        severity: str,
        rule_id: str,
        description: str,
        technical_remediation: str,
        user_impact: str,
        confidence: str = "heuristic",
        selector: str | None = None,
        value: Any = None,
        threshold: Any = None,
    ) -> dict[str, Any]:
        issue = ux_finding_defaults(
            scanner,
            category,
            page_url,
            "server",
            title=title,
            severity=severity,
            confidence=confidence,
            selector=selector,
            evidence={
                "rule_id": rule_id,
                "description": description,
                "metric": rule_id,
                "value": value,
                "threshold": threshold,
            },
            user_impact=user_impact,
            technical_remediation=technical_remediation,
            references=[],
        )
        issue["builder_prompt"] = build_builder_prompt(issue)
        return issue

    def _rendered_surface(self, page_url: str) -> dict[str, Any]:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                return page.evaluate(
                    """
                    () => ({
                      scripts: Array.from(document.scripts).map((script) => script.src).filter(Boolean),
                      forms: Array.from(document.querySelectorAll('form')).map((form, index) => ({
                        action: form.getAttribute('action') || location.href,
                        method: (form.getAttribute('method') || 'GET').toUpperCase(),
                        selector: form.id ? `#${form.id}` : `form:nth-of-type(${index + 1})`,
                        inputTypes: Array.from(form.querySelectorAll('input, textarea, select')).map((el) => ({
                          type: (el.getAttribute('type') || el.tagName || '').toLowerCase(),
                          name: el.getAttribute('name') || '',
                          autocomplete: el.getAttribute('autocomplete') || '',
                        })),
                        text: (form.textContent || '').toLowerCase().slice(0, 2000),
                      })),
                      pageText: (document.body?.innerText || '').toLowerCase().slice(0, 5000),
                    })
                    """
                )
            finally:
                browser.close()

    def _classify_forms(self, page_url: str, forms: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        issues: list[dict[str, Any]] = []
        matrix: list[dict[str, Any]] = []
        for form in forms:
            input_types = [str(item.get("type") or "") for item in form.get("inputTypes", [])]
            names = " ".join(str(item.get("name") or "") for item in form.get("inputTypes", [])).lower()
            text = str(form.get("text") or "")
            is_auth = "password" in input_types or any(term in text or term in names for term in ("login", "sign in", "signup", "register", "password"))
            is_upload = "file" in input_types
            is_payment = any(term in text or term in names for term in ("card", "payment", "checkout", "cvv", "coupon"))
            is_destructive = any(term in text or term in names for term in ("delete", "remove", "cancel", "deactivate"))
            testable = not (is_upload or is_payment or is_destructive)
            matrix.append({
                "selector": form.get("selector"),
                "action": self._resolve_url(page_url, str(form.get("action") or "")) or form.get("action"),
                "method": form.get("method"),
                "classification": "auth" if is_auth else "upload" if is_upload else "payment" if is_payment else "destructive" if is_destructive else "general",
                "safe_to_submit": testable,
            })
            if is_upload:
                issues.append(self._issue(
                    "app_controls",
                    "Upload Checks",
                    page_url,
                    title="File upload form requires manual validation before launch",
                    severity="medium",
                    rule_id="upload-form-detected",
                    description=f"Upload-capable form found at {form.get('selector')}.",
                    selector=form.get("selector"),
                    user_impact="Unvalidated uploads can expose malware, storage abuse, or content-type bypass risks.",
                    technical_remediation="Restrict allowed file types, verify content server-side, scan uploads, and store files outside executable paths.",
                ))
            if is_payment:
                issues.append(self._issue(
                    "app_controls",
                    "Business Logic Abuse",
                    page_url,
                    title="Payment or coupon form requires launch abuse review",
                    severity="medium",
                    rule_id="payment-abuse-review",
                    description=f"Payment/coupon-related form found at {form.get('selector')}.",
                    selector=form.get("selector"),
                    user_impact="Coupon, checkout, and trial flows are common targets for business-logic abuse.",
                    technical_remediation="Add server-side validation, rate limits, replay protection, audit logs, and test-mode payment controls before launch.",
                ))
        return issues, matrix

    def _has_auth_surface(
        self,
        *,
        page_text: str,
        form_matrix: list[dict[str, Any]],
        discovered_endpoints: list[str],
        protected_paths: list[str] | None,
        auth_test_accounts: list[dict[str, Any]] | None,
    ) -> bool:
        if auth_test_accounts:
            return True
        if protected_paths:
            return True
        if any(form.get("classification") == "auth" for form in form_matrix):
            return True
        lowered_endpoints = " ".join(discovered_endpoints).lower()
        if any(term in lowered_endpoints for term in self.AUTH_PATH_TERMS):
            return True
        text = page_text.lower()
        return "password" in text and any(term in text for term in ("login", "sign in", "signin", "account", "admin"))

    def _has_account_creation_surface(
        self,
        *,
        page_text: str,
        form_matrix: list[dict[str, Any]],
        discovered_endpoints: list[str],
    ) -> bool:
        lowered_endpoints = " ".join(discovered_endpoints).lower()
        if any(term in lowered_endpoints for term in self.ACCOUNT_CREATION_TERMS):
            return True
        text = page_text.lower()
        if any(term in text for term in self.ACCOUNT_CREATION_TERMS):
            return True
        for form in form_matrix:
            if form.get("classification") != "auth":
                continue
            action = str(form.get("action") or "").lower()
            if any(term in action for term in self.ACCOUNT_CREATION_TERMS):
                return True
        return False

    def _extract_js_endpoints(self, base_url: str, scripts: list[str]) -> tuple[list[str], list[dict[str, Any]]]:
        endpoints: list[str] = []
        js_files: list[dict[str, Any]] = []
        seen: set[str] = set()
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            for script in scripts[: settings.app_controls_max_js_files]:
                script_url = self._resolve_url(base_url, script)
                if not script_url or script_url in seen:
                    continue
                seen.add(script_url)
                try:
                    response = client.get(script_url, headers={"User-Agent": "WVS-AppControls/1.0"})
                except httpx.HTTPError:
                    continue
                if response.status_code >= 400:
                    continue
                body = response.text
                found = []
                for match in self.ENDPOINT_RE.findall(body):
                    endpoint = self._resolve_url(base_url, match)
                    if endpoint and endpoint not in endpoints:
                        endpoints.append(endpoint)
                        found.append(endpoint)
                    if len(endpoints) >= settings.app_controls_max_endpoints:
                        break
                js_files.append({"url": script_url, "endpoints": found[:20]})
                if len(endpoints) >= settings.app_controls_max_endpoints:
                    break
        return endpoints, js_files

    def _discover_openapi(self, base_url: str) -> tuple[list[str], list[dict[str, Any]]]:
        specs: list[dict[str, Any]] = []
        endpoints: list[str] = []
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            for path in self.COMMON_API_SPECS:
                spec_url = self._resolve_url(base_url, path)
                if not spec_url:
                    continue
                try:
                    response = client.get(spec_url, headers={"User-Agent": "WVS-AppControls/1.0"})
                except httpx.HTTPError:
                    continue
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    continue
                try:
                    payload = response.json()
                except json.JSONDecodeError:
                    continue
                paths = payload.get("paths") if isinstance(payload, dict) else {}
                if not isinstance(paths, dict):
                    continue
                found = []
                for api_path in paths.keys():
                    endpoint = self._resolve_url(base_url, str(api_path))
                    if endpoint:
                        endpoints.append(endpoint)
                        found.append(endpoint)
                specs.append({"url": spec_url, "endpoint_count": len(found), "endpoints": found[:20]})
        return endpoints[: settings.app_controls_max_endpoints], specs

    def _check_cors(self, endpoints: list[str]) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
            for endpoint in endpoints[:20]:
                try:
                    response = client.options(
                        endpoint,
                        headers={
                            "Origin": "https://evil.example",
                            "Access-Control-Request-Method": "GET",
                            "User-Agent": "WVS-AppControls/1.0",
                        },
                    )
                except httpx.HTTPError:
                    continue
                allow_origin = response.headers.get("access-control-allow-origin", "")
                allow_credentials = response.headers.get("access-control-allow-credentials", "").lower()
                if allow_origin == "*" and allow_credentials == "true":
                    issues.append(self._issue(
                        "app_controls",
                        "API CORS",
                        endpoint,
                        title="CORS allows credentials with wildcard origin",
                        severity="high",
                        confidence="measured",
                        rule_id="cors-wildcard-credentials",
                        description="Response included Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.",
                        user_impact="Browsers may expose authenticated API responses to untrusted origins if deployed with this configuration.",
                        technical_remediation="Use an explicit allowlist of trusted origins and avoid credentialed wildcard CORS.",
                    ))
                elif allow_origin == "https://evil.example" and allow_credentials == "true":
                    issues.append(self._issue(
                        "app_controls",
                        "API CORS",
                        endpoint,
                        title="CORS reflects untrusted origins with credentials",
                        severity="high",
                        confidence="measured",
                        rule_id="cors-reflected-origin",
                        description="Response reflected an untrusted Origin while allowing credentials.",
                        user_impact="Attackers can host a page that reads authenticated API responses from user browsers.",
                        technical_remediation="Replace reflected-origin CORS with a strict trusted-origin allowlist.",
                    ))
        return issues

    def _discover_common_surface(self, base_url: str, paths: tuple[str, ...], category: str, title: str, severity: str) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
            for path in paths:
                target = self._resolve_url(base_url, path)
                if not target:
                    continue
                try:
                    response = client.get(target, headers={"User-Agent": "WVS-AppControls/1.0"})
                except httpx.HTTPError:
                    continue
                if response.status_code in {404, 410} or response.status_code >= 500:
                    continue
                issues.append(self._issue(
                    "app_controls",
                    category,
                    target,
                    title=title,
                    severity=severity,
                    confidence="heuristic",
                    rule_id=category.lower().replace(" ", "-"),
                    description=f"{path} responded with HTTP {response.status_code}. Authentication, authorization, and signature verification were not confirmed by this passive check.",
                    user_impact="Public webhook, callback, or upload routes are sometimes intentional, but they need explicit controls before launch.",
                    technical_remediation="Verify authentication, signature verification, environment gating, file validation, and logging for this route; remove it if it is unused.",
                ))
        return issues

    def _check_auth_login(self, base_url: str, login_path: str, account: dict[str, Any]) -> tuple[dict[str, Any] | None, httpx.Cookies]:
        cookies = httpx.Cookies()
        login_url = self._resolve_url(base_url, login_path)
        if not login_url:
            return None, cookies
        identifier = account.get("email") or account.get("username")
        with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
            try:
                response = client.post(
                    login_url,
                    json={"email": identifier, "username": identifier, "identifier": identifier, "password": account.get("password")},
                    headers={"User-Agent": "WVS-AppControls/1.0"},
                )
            except httpx.HTTPError as exc:
                return self._issue(
                    "app_controls",
                    "Authenticated Flow",
                    login_url,
                    title="Test-account login request failed",
                    severity="medium",
                    rule_id="auth-login-request-failed",
                    description=f"Login check failed with {type(exc).__name__}.",
                    user_impact="Authenticated checks could not validate protected areas.",
                    technical_remediation="Provide a working staging test account and login path for launch checks.",
                ), cookies
            cookies = client.cookies
        if response.status_code in {401, 403}:
            return self._issue(
                "app_controls",
                "Authenticated Flow",
                login_url,
                title="Test-account login was rejected",
                severity="medium",
                confidence="measured",
                rule_id="auth-login-rejected",
                description=f"Login returned HTTP {response.status_code}.",
                user_impact="Authenticated flow checks cannot validate dashboard, role, timeout, or access-control behavior.",
                technical_remediation="Provide valid staging credentials for at least one test account.",
            ), cookies
        return None, cookies

    def _check_protected_paths(self, base_url: str, protected_paths: list[str], cookies: httpx.Cookies | None) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        with httpx.Client(timeout=self.timeout, follow_redirects=False, cookies=cookies) as authed:
            with httpx.Client(timeout=self.timeout, follow_redirects=False) as anon:
                for raw_path in protected_paths:
                    target = self._resolve_url(base_url, raw_path)
                    if not target:
                        continue
                    try:
                        anon_response = anon.get(target, headers={"User-Agent": "WVS-AppControls/1.0"})
                    except httpx.HTTPError:
                        continue
                    if anon_response.status_code < 400:
                        issues.append(self._issue(
                            "app_controls",
                            "Broken Access Control",
                            target,
                            title="Protected path is reachable without authentication",
                            severity="high",
                            confidence="measured",
                            rule_id="protected-path-public",
                            description=f"Anonymous request to {raw_path} returned HTTP {anon_response.status_code}.",
                            user_impact="Private dashboards or user data may be exposed to unauthenticated visitors.",
                            technical_remediation="Require server-side authentication and authorization before rendering this route or API response.",
                        ))
                    if cookies:
                        try:
                            authed_response = authed.get(target, headers={"User-Agent": "WVS-AppControls/1.0"})
                        except httpx.HTTPError:
                            continue
                        if authed_response.status_code in {401, 403}:
                            issues.append(self._issue(
                                "app_controls",
                                "Authenticated Flow",
                                target,
                                title="Authenticated test account could not access expected protected path",
                                severity="medium",
                                confidence="measured",
                                rule_id="protected-path-authed-denied",
                                description=f"Authenticated request to {raw_path} returned HTTP {authed_response.status_code}.",
                                user_impact="Launch-critical dashboard or account flows may be broken for real users.",
                                technical_remediation="Confirm routing, session cookie settings, and role permissions for the supplied test account.",
                            ))
        return issues

    def _check_enumeration(self, base_url: str, paths: list[str]) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
            for raw_path in paths:
                if not any(term in raw_path.lower() for term in ("login", "signin", "reset", "forgot", "signup", "register")):
                    continue
                target = self._resolve_url(base_url, raw_path)
                if not target:
                    continue
                payloads = [
                    {"email": "known-test@example.invalid", "identifier": "known-test@example.invalid", "password": "WrongPassword123!"},
                    {"email": "unknown-test@example.invalid", "identifier": "unknown-test@example.invalid", "password": "WrongPassword123!"},
                ]
                try:
                    responses = [client.post(target, json=payload, headers={"User-Agent": "WVS-AppControls/1.0"}) for payload in payloads]
                except httpx.HTTPError:
                    continue
                body_a = responses[0].text[:500].strip().lower()
                body_b = responses[1].text[:500].strip().lower()
                if responses[0].status_code != responses[1].status_code or body_a != body_b:
                    issues.append(self._issue(
                        "app_controls",
                        "User Enumeration",
                        target,
                        title="Auth endpoint may reveal account existence",
                        severity="medium",
                        confidence="heuristic",
                        rule_id="user-enumeration-differential-response",
                        description="Two invalid account identifiers produced different status codes or response bodies.",
                        user_impact="Attackers may confirm which emails or usernames exist before credential attacks.",
                        technical_remediation="Return uniform messages, status codes, and timing for valid and invalid identifiers.",
                    ))
        return issues

    def _check_idor_templates(self, base_url: str, idor_paths: list[str], accounts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not idor_paths or len(accounts) < 2:
            return []
        return [
            self._issue(
                "app_controls",
                "Broken Access Control",
                self._resolve_url(base_url, idor_paths[0]) or base_url,
                title="IDOR checks need two authenticated sessions",
                severity="informational",
                rule_id="idor-two-session-required",
                description="IDOR path templates were supplied, but automated cross-account replay is not yet configured for this route shape.",
                user_impact="Object-level authorization defects can expose another user's records after launch.",
                technical_remediation="Provide two staging accounts and path templates with object IDs owned by each account for cross-account replay testing.",
            )
        ]

    def scan(
        self,
        url: str,
        *,
        page_paths: list[str] | None = None,
        active_check_paths: list[str] | None = None,
        auth_test_accounts: list[dict[str, Any]] | None = None,
        protected_paths: list[str] | None = None,
        idor_paths: list[str] | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        if not enabled or not settings.app_controls_enabled:
            return {"status": "disabled", "issues": [], "recommendations": [], "score": None}

        pages = build_page_targets(url, page_paths)
        issues: list[dict[str, Any]] = []
        scripts: list[str] = []
        form_matrix: list[dict[str, Any]] = []
        page_text = ""

        for page_url in pages:
            try:
                surface = self._rendered_surface(page_url)
            except PlaywrightTimeoutError:
                issues.append(self._issue(
                    "app_controls",
                    "App Surface",
                    page_url,
                    title="Page app controls could not be evaluated",
                    severity="medium",
                    confidence="measured",
                    rule_id="app-controls-page-timeout",
                    description="The page did not finish loading before app-control extraction timed out.",
                    user_impact="Hidden routes, forms, and scripts on this page may remain untested.",
                    technical_remediation="Reduce page load blockers so pre-production checks can complete.",
                ))
                continue
            scripts.extend(surface.get("scripts") or [])
            page_text += " " + str(surface.get("pageText") or "")
            form_issues, matrix = self._classify_forms(page_url, surface.get("forms") or [])
            issues.extend(form_issues)
            form_matrix.extend(matrix)

        js_endpoints, js_files = self._extract_js_endpoints(url, scripts)
        openapi_endpoints, openapi_specs = self._discover_openapi(url)
        discovered_endpoints = list(dict.fromkeys([*js_endpoints, *openapi_endpoints]))[: settings.app_controls_max_endpoints]
        issues.extend(self._check_cors(discovered_endpoints or [self._origin(url)]))
        issues.extend(self._discover_common_surface(url, self.WEBHOOK_PATHS, "Webhook Checks", "Public webhook or callback route needs verification", "medium"))
        issues.extend(self._discover_common_surface(url, self.UPLOAD_PATHS, "Upload Checks", "Public upload route needs verification", "medium"))

        accounts = auth_test_accounts or []
        has_auth_surface = self._has_auth_surface(
            page_text=page_text,
            form_matrix=form_matrix,
            discovered_endpoints=discovered_endpoints,
            protected_paths=protected_paths,
            auth_test_accounts=accounts,
        )
        has_account_creation_surface = self._has_account_creation_surface(
            page_text=page_text,
            form_matrix=form_matrix,
            discovered_endpoints=discovered_endpoints,
        )
        skipped_controls = []

        has_mfa_signal = any(term in page_text for term in self.MFA_TERMS)
        has_email_verify_signal = any(term in page_text for term in self.EMAIL_VERIFY_TERMS)

        if has_auth_surface and not has_mfa_signal:
            issues.append(self._issue(
                "app_controls",
                "MFA and Verification",
                url,
                title="No MFA signal detected on rendered auth pages",
                severity="low",
                rule_id="mfa-signal-missing",
                description="Rendered pages did not include common MFA/OTP/authenticator language.",
                user_impact="Launch-critical accounts may lack a second-factor option.",
                technical_remediation="Add MFA for admin and high-risk user accounts, or document why it is not required for this app.",
            ))
        elif not has_auth_surface:
            skipped_controls.append({
                "control": "mfa-signal",
                "reason": "No login, account, admin, protected route, or test-account surface was detected.",
            })

        if has_account_creation_surface and not has_email_verify_signal:
            issues.append(self._issue(
                "app_controls",
                "MFA and Verification",
                url,
                title="No email-verification signal detected",
                severity="low",
                rule_id="email-verification-signal-missing",
                description="Rendered pages did not include common email-verification language.",
                user_impact="Fake or mistyped accounts may reach protected workflows after launch.",
                technical_remediation="Require email verification before access to sensitive or abuse-prone workflows.",
            ))
        elif not has_account_creation_surface:
            skipped_controls.append({
                "control": "email-verification-signal",
                "reason": "No signup, registration, or account-creation surface was detected.",
            })

        login_candidates = active_check_paths or ["/login", "/signin", "/api/login", "/api/auth/login"]
        cookies = None
        if accounts:
            login_issue, cookies = self._check_auth_login(url, login_candidates[0], accounts[0])
            if login_issue:
                issues.append(login_issue)
        issues.extend(self._check_protected_paths(url, protected_paths or ["/dashboard", "/account", "/settings", "/admin"], cookies))
        issues.extend(self._check_enumeration(url, login_candidates))
        issues.extend(self._check_idor_templates(url, idor_paths or [], accounts))

        normalized = normalize_ux_findings(issues, default_scanner="app_controls", default_category="Application Controls")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "discovered_endpoints": discovered_endpoints,
            "javascript_files": js_files,
            "openapi_specs": openapi_specs,
            "form_matrix": form_matrix,
            "app_classification": {
                "auth_surface_detected": has_auth_surface,
                "account_creation_surface_detected": has_account_creation_surface,
            },
            "skipped_controls": skipped_controls,
            "score": max(0, 100 - len([item for item in normalized if item.get("severity") in {"critical", "high", "medium"}]) * 8),
            "recommendations": [
                "Review discovered JavaScript and OpenAPI endpoints before launch.",
                "Provide two staging test accounts to enable deeper authenticated and IDOR checks.",
                "Protect upload, webhook, callback, dashboard, and admin routes with server-side controls.",
            ] if normalized else [],
        }
