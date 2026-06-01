from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

# URL parameters commonly used for redirects
_REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_to", "redirect_url", "return",
    "return_to", "returnurl", "returnto", "goto", "dest", "destination",
    "continue", "target", "link", "redir", "r", "u", "path", "forward",
    "location", "out", "view", "logoutRedirect", "successUrl", "failureUrl",
    "callback", "ref", "referer", "referrer", "origin",
]

# External domain payloads — use an obviously external hostname
_EXTERNAL_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "https://evil.example.com/",
    "https:evil.example.com",
    "/\\evil.example.com",
    "///evil.example.com",
    "////evil.example.com",
    "https://evil.example.com%23@trusted.com",   # fragment bypass
    "https://trusted.com@evil.example.com",       # userinfo bypass
    "https://evil.example.com%2F%2F",             # double URL-encoded slash
]

_SEVERITY_WEIGHT = {"High": 20, "Medium": 12, "Low": 5}


def _is_external_redirect(original_host: str, location: str) -> bool:
    if not location:
        return False
    try:
        parsed = urlparse(location if location.startswith("http") else f"https:{location}" if location.startswith("//") else f"https://x{location}")
        dest_host = parsed.hostname or ""
        return dest_host and dest_host.lower() != original_host.lower()
    except Exception:
        return False


class OpenRedirectScanner:
    def __init__(self, timeout: int = 3, max_requests: int = 24, deadline_seconds: int = 45):
        self.max_requests = max_requests
        self.deadline_seconds = deadline_seconds
        self.client = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=2),
            follow_redirects=False,
            headers={"User-Agent": "WVS-RedirectScanner/1.0"},
        )

    def _extract_redirect_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        params_in_url = list(parse_qs(parsed.query).keys())
        found = [p for p in params_in_url if p.lower() in {r.lower() for r in _REDIRECT_PARAMS}]
        return found or _REDIRECT_PARAMS[:8]

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        return urlunparse(parsed._replace(query=new_query))

    def _probe(self, base_url: str, host: str, issues: list, seen_params: set, budget: dict) -> None:
        params_to_test = self._extract_redirect_params(base_url)

        for param in params_to_test:
            for payload in _EXTERNAL_PAYLOADS:
                if budget["requests"] >= self.max_requests or time.monotonic() >= budget["deadline"]:
                    return

                test_url = self._inject_param(base_url, param, payload)
                dedup_key = f"{param}:{payload}"
                if dedup_key in seen_params:
                    continue
                seen_params.add(dedup_key)
                budget["requests"] += 1

                try:
                    resp = self.client.get(test_url)
                except Exception:
                    continue

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if _is_external_redirect(host, location):
                        issues.append({
                            "name": "Open redirect",
                            "severity": "High",
                            "evidence": f"Parameter '{param}' with payload '{payload}' redirected to: {location}",
                            "url": test_url,
                            "parameter": param,
                            "location": location,
                        })
                        return  # one confirmed finding per endpoint is enough

    def _find_forms_with_redirect_actions(self, url: str) -> list[str]:
        try:
            resp = self.client.get(url)
            if resp.status_code != 200:
                return []
        except Exception:
            return []

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        endpoints: list[str] = []
        base = urlparse(url)
        host = base.hostname or ""

        for form in soup.find_all("form"):
            action = form.get("action", "")
            if not action:
                continue
            if action.startswith("http"):
                form_url = action
            else:
                form_url = urlunparse(base._replace(path=action, query=""))

            # Only probe forms on the same host
            if urlparse(form_url).hostname == host:
                endpoints.append(form_url)

        return endpoints[:5]

    def scan(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        issues: list[dict] = []
        seen_params: set[str] = set()
        budget = {"requests": 0, "deadline": time.monotonic() + self.deadline_seconds}

        # Probe the target URL itself
        self._probe(url, host, issues, seen_params, budget)

        # Also probe common redirect-bearing paths if the base URL has no query params
        if not parsed.query and budget["requests"] < self.max_requests and time.monotonic() < budget["deadline"]:
            for suffix in ["/login", "/logout", "/signin", "/auth/callback", "/oauth/callback", "/sso"]:
                if budget["requests"] >= self.max_requests or time.monotonic() >= budget["deadline"]:
                    break
                candidate = urlunparse(parsed._replace(path=suffix, query=""))
                self._probe(candidate, host, issues, seen_params, budget)

        recs: list[str] = []
        if issues:
            recs.append("Validate redirect targets against a strict allowlist of known-safe internal paths.")
            recs.append("Never use user-supplied values directly in Location headers — map them to server-side codes.")
            recs.append("If external redirects are required, display a confirmation interstitial showing the destination.")

        penalty = sum(_SEVERITY_WEIGHT.get(i["severity"], 5) for i in issues)
        score = max(0, 100 - penalty)

        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "recommendations": recs,
            "score": score,
            "params_tested": list(seen_params),
            "requests_made": budget["requests"],
            "truncated": budget["requests"] >= self.max_requests or time.monotonic() >= budget["deadline"],
        }

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
