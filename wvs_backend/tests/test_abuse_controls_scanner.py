from __future__ import annotations

import httpx

from app.scanners.abuse_controls_scanner import AbuseControlsScanner
from app.utils.scan_helpers import build_scan_sections, build_scan_summary


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.calls: list[tuple[str, str]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        if url.endswith("/login"):
            return httpx.Response(200, text="<form>login password</form>", request=httpx.Request("GET", url))
        if url.endswith("/admin"):
            return httpx.Response(200, text="admin console", request=httpx.Request("GET", url))
        return httpx.Response(404, request=httpx.Request("GET", url))

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))


def test_abuse_controls_discovers_auth_and_sensitive_routes(monkeypatch):
    monkeypatch.setattr("app.scanners.abuse_controls_scanner.httpx.Client", FakeClient)

    result = AbuseControlsScanner().discover_routes("https://example.com")

    routes = result["routes"]
    assert any(route["path"] == "/login" and route["kind"] == "auth" for route in routes)
    assert any(route["path"] == "/admin" and route["kind"] == "sensitive" for route in routes)
    assert result["issues"][0]["scanner"] == "route_discovery"


def test_abuse_controls_uses_discovered_auth_routes_for_rate_limit_checks(monkeypatch):
    monkeypatch.setattr("app.scanners.abuse_controls_scanner.httpx.Client", FakeClient)

    result = AbuseControlsScanner().scan("https://example.com", enabled=True, budget=3)

    assert result["status"] == "issues_found"
    assert result["issues"][0]["scanner"] == "abuse_controls"
    assert result["issues"][0]["severity"] == "high"
    assert result["observations"][0]["requests_sent"] == 3


def test_abuse_controls_flow_into_summary_and_sections():
    findings = {
        "abuse_controls": {
            "status": "issues_found",
            "issues": [
                {
                    "title": "No rate limiting observed on active endpoint",
                    "severity": "high",
                    "confidence": "measured",
                    "evidence": {"description": "POST /login accepted 3 requests."},
                }
            ],
            "discovery": {
                "issues": [
                    {
                        "title": "Sensitive route is reachable before launch",
                        "severity": "medium",
                        "confidence": "heuristic",
                        "evidence": {"description": "/admin responded with HTTP 200."},
                    }
                ]
            },
        }
    }

    summary = build_scan_summary(findings)
    sections = build_scan_sections(findings)

    assert summary["abuse_control_issue_count"] == 1
    assert summary["exposed_route_issue_count"] == 1
    assert summary["launch_blocker_count"] == 1
    assert sections["abuse_controls"]["issue_count"] == 2
