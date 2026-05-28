from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from app.settings import settings
from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.scan_helpers import normalize_target_url


@dataclass(frozen=True)
class ActiveEndpoint:
    method: str
    url: str
    label: str


class AbuseControlsScanner:
    """Bounded pre-production checks for throttling and abuse controls."""

    DISCOVERY_PATHS = (
        "/login",
        "/signin",
        "/sign-in",
        "/auth/login",
        "/api/login",
        "/api/auth/login",
        "/register",
        "/signup",
        "/sign-up",
        "/api/register",
        "/api/signup",
        "/forgot-password",
        "/reset-password",
        "/password/reset",
        "/api/password/reset",
        "/admin",
        "/dashboard",
        "/api/admin",
    )
    AUTH_KEYWORDS = (
        "login",
        "signin",
        "sign-in",
        "signup",
        "sign-up",
        "register",
        "forgot",
        "reset",
        "password",
        "auth",
        "session",
    )
    SENSITIVE_KEYWORDS = (
        "admin",
        "dashboard",
        "console",
        "portal",
        "internal",
    )
    CONTROL_HEADERS = {
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
    }
    CONTROL_TEXT = (
        "too many requests",
        "rate limit",
        "rate-limit",
        "retry later",
        "slow down",
        "cooldown",
        "temporarily blocked",
        "captcha",
        "recaptcha",
        "hcaptcha",
    )

    def _parse_endpoint(self, base_url: str, raw_endpoint: str) -> ActiveEndpoint | None:
        parsed_base = urlparse(normalize_target_url(base_url))
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        raw = raw_endpoint.strip()
        if not raw:
            return None

        method = "POST"
        target = raw
        parts = raw.split(maxsplit=1)
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST"}:
            method = parts[0].upper()
            target = parts[1].strip()

        candidate = normalize_target_url(urljoin(origin + "/", target))
        parsed_candidate = urlparse(candidate)
        if parsed_candidate.netloc != parsed_base.netloc:
            return None
        return ActiveEndpoint(method=method, url=candidate, label=raw)

    def _has_control_signal(self, response: httpx.Response) -> tuple[bool, str]:
        lowered_headers = {key.lower(): value for key, value in response.headers.items()}
        if response.status_code == 429:
            return True, "Target returned HTTP 429."
        for header in self.CONTROL_HEADERS:
            if header in lowered_headers:
                if header.endswith("remaining") and lowered_headers[header].strip() not in {"", "0"}:
                    continue
                return True, f"Target returned {header}."
        body_sample = response.text[:2000].lower()
        for phrase in self.CONTROL_TEXT:
            if phrase in body_sample:
                return True, f"Target response mentioned {phrase}."
        return False, ""

    def _request(self, client: httpx.Client, endpoint: ActiveEndpoint, index: int) -> httpx.Response:
        headers = {
            "User-Agent": "WVS-PreProduction-AbuseControls/1.0",
            "X-WVS-Active-Test": "rate-limit-check",
        }
        if endpoint.method == "GET":
            return client.get(endpoint.url, headers=headers, params={"wvs_active_check": str(index)})
        return client.post(
            endpoint.url,
            headers=headers,
            json={
                "email": "wvs-rate-limit-check@example.invalid",
                "username": "wvs-rate-limit-check",
                "password": "WVSRateLimitCheck123!",
                "wvs_active_check": index,
            },
        )

    def _classify_route(self, path: str, response: httpx.Response) -> tuple[str, str]:
        haystack = f"{path} {response.headers.get('location', '')} {response.text[:2000]}".lower()
        if any(keyword in haystack for keyword in self.SENSITIVE_KEYWORDS):
            return "sensitive", "Sensitive pre-production route is reachable."
        if any(keyword in haystack for keyword in self.AUTH_KEYWORDS):
            return "auth", "Authentication or account-management route is reachable."
        return "unknown", "Route responded but did not match a known auth/admin pattern."

    def discover_routes(self, url: str) -> dict:
        if not settings.abuse_scan_enabled:
            return {"status": "disabled", "routes": [], "issues": [], "recommendations": []}

        parsed_base = urlparse(normalize_target_url(url))
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        routes: list[dict] = []
        issues: list[dict] = []

        with httpx.Client(
            timeout=settings.abuse_scan_timeout_seconds,
            follow_redirects=False,
            verify=True,
        ) as client:
            for path in self.DISCOVERY_PATHS:
                route_url = normalize_target_url(urljoin(origin + "/", path.lstrip("/")))
                try:
                    response = client.get(
                        route_url,
                        headers={
                            "User-Agent": "WVS-PreProduction-RouteDiscovery/1.0",
                            "X-WVS-Active-Test": "route-discovery",
                        },
                    )
                except httpx.HTTPError:
                    continue
                if response.status_code in {404, 410}:
                    continue
                if response.status_code >= 500:
                    continue

                kind, reason = self._classify_route(path, response)
                route = {
                    "path": path,
                    "url": route_url,
                    "status_code": response.status_code,
                    "kind": kind,
                    "method": "GET",
                    "reason": reason,
                }
                routes.append(route)

                if kind == "sensitive" and response.status_code < 400:
                    issue = {
                        "scanner": "route_discovery",
                        "category": "Exposed Routes",
                        "title": "Sensitive route is reachable before launch",
                        "severity": "medium",
                        "confidence": "heuristic",
                        "page_url": route_url,
                        "viewport": "server",
                        "evidence": {
                            "rule_id": "sensitive-route-reachable",
                            "description": f"{path} responded with HTTP {response.status_code}.",
                        },
                        "user_impact": "Attackers commonly enumerate admin and dashboard routes before launch.",
                        "technical_remediation": "Require authentication, remove unused routes, or restrict pre-production admin surfaces by environment and network.",
                    }
                    issue["builder_prompt"] = build_builder_prompt(issue)
                    issues.append(issue)

        return {
            "status": "issues_found" if issues else ("ok" if routes else "not_found"),
            "routes": routes,
            "issues": normalize_ux_findings(issues, default_scanner="route_discovery", default_category="Exposed Routes"),
            "recommendations": [
                "Remove unused auth/admin routes before launch and protect remaining routes with authentication.",
                "Do not rely on obscure paths; attackers enumerate common routes automatically.",
            ] if routes else [
                "No common auth or admin routes were reachable from the public origin."
            ],
        }

    def scan(
        self,
        url: str,
        *,
        endpoints: list[str] | None = None,
        budget: int | None = None,
        enabled: bool = False,
    ) -> dict:
        if not enabled:
            return {"status": "disabled", "issues": [], "recommendations": [], "score": None}
        if not settings.abuse_scan_enabled:
            return {"status": "disabled", "issues": [], "recommendations": ["Active abuse-control scanning is disabled."], "score": None}

        discovery = self.discover_routes(url)
        discovered_auth_paths = [
            f"POST {route['path']}"
            for route in discovery.get("routes", [])
            if route.get("kind") == "auth"
        ]
        requested = endpoints or discovered_auth_paths
        parsed_endpoints = [self._parse_endpoint(url, item) for item in requested]
        active_endpoints = [item for item in parsed_endpoints if item is not None]
        if not active_endpoints:
            return {
                "status": "not_configured",
                "issues": [],
                "discovery": discovery,
                "recommendations": ["Add explicit login, signup, password reset, contact, or costly API paths to test abuse controls."],
                "score": None,
            }

        request_budget = max(3, min(int(budget or settings.abuse_scan_default_budget), settings.abuse_scan_max_budget))
        issues: list[dict] = []
        observations: list[dict] = []

        with httpx.Client(
            timeout=settings.abuse_scan_timeout_seconds,
            follow_redirects=False,
            verify=True,
        ) as client:
            for endpoint in active_endpoints:
                status_codes: list[int | str] = []
                control_detected = False
                control_reason = ""

                for index in range(1, request_budget + 1):
                    try:
                        response = self._request(client, endpoint, index)
                        status_codes.append(response.status_code)
                        detected, reason = self._has_control_signal(response)
                        if detected:
                            control_detected = True
                            control_reason = reason
                            break
                    except httpx.HTTPError as exc:
                        status_codes.append(type(exc).__name__)
                        break

                observations.append(
                    {
                        "endpoint": endpoint.label,
                        "method": endpoint.method,
                        "url": endpoint.url,
                        "requests_sent": len(status_codes),
                        "status_codes": status_codes,
                        "control_detected": control_detected,
                        "control_reason": control_reason,
                    }
                )

                if not control_detected and len(status_codes) >= request_budget:
                    issue = {
                        "scanner": "abuse_controls",
                        "category": "Abuse Controls",
                        "title": "No rate limiting observed on active endpoint",
                        "severity": "high",
                        "confidence": "measured",
                        "page_url": endpoint.url,
                        "viewport": "server",
                        "evidence": {
                            "rule_id": "rate-limit-missing",
                            "description": f"{endpoint.method} {endpoint.label} accepted {request_budget} bounded test requests without a rate-limit signal.",
                            "metric": "requests_without_throttle",
                            "value": request_budget,
                            "threshold": 1,
                        },
                        "user_impact": "Attackers or bots may abuse this endpoint after launch, causing account attacks, spam, quota exhaustion, or avoidable infrastructure cost.",
                        "technical_remediation": "Add per-IP and per-account throttling, return HTTP 429 with Retry-After when limits are exceeded, and log repeated abuse attempts.",
                        "references": ["OWASP WSTG-ATHN-03"],
                    }
                    issue["builder_prompt"] = build_builder_prompt(issue)
                    issues.append(issue)

        normalized = normalize_ux_findings(issues, default_scanner="abuse_controls", default_category="Abuse Controls")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "discovery": discovery,
            "observations": observations,
            "score": max(0, 100 - len(normalized) * 25),
            "recommendations": [
                "Protect login, signup, password reset, contact, and paid or AI-backed endpoints with explicit rate limits.",
                "Return HTTP 429 and Retry-After when throttles trigger so clients and monitoring can detect the control.",
                "Use separate per-IP, per-account, and per-endpoint quotas for pre-production launch checks.",
            ] if normalized else [
                "Keep these active checks in the pre-production release checklist and re-run them after auth or API changes."
            ],
        }
