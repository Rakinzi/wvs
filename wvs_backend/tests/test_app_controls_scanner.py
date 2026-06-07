from __future__ import annotations

import httpx

from app.scanners.app_controls_scanner import AppControlsScanner
from app.utils.scan_helpers import build_scan_sections, build_scan_summary


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.cookies = httpx.Cookies()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url, **kwargs):
        if url.endswith("/app.js"):
            return httpx.Response(200, text="'/api/users'; fetch('/api/admin')", request=httpx.Request("GET", url))
        if url.endswith("/openapi.json"):
            return httpx.Response(
                200,
                json={"paths": {"/api/projects": {"get": {}}, "/api/users/{id}": {"get": {}}}},
                headers={"content-type": "application/json"},
                request=httpx.Request("GET", url),
            )
        if url.endswith("/webhook") or url.endswith("/upload") or url.endswith("/dashboard"):
            return httpx.Response(200, text="ok", request=httpx.Request("GET", url))
        return httpx.Response(404, request=httpx.Request("GET", url))

    def options(self, url, **kwargs):
        return httpx.Response(
            204,
            headers={
                "access-control-allow-origin": "https://evil.example",
                "access-control-allow-credentials": "true",
            },
            request=httpx.Request("OPTIONS", url),
        )

    def post(self, url, **kwargs):
        return httpx.Response(200, text="invalid", request=httpx.Request("POST", url))


def test_app_controls_extracts_js_openapi_and_cors_issues(monkeypatch):
    scanner = AppControlsScanner()
    monkeypatch.setattr("app.scanners.app_controls_scanner.httpx.Client", FakeClient)
    monkeypatch.setattr(
        scanner,
        "_rendered_surface",
        lambda page_url: {
            "scripts": ["https://example.com/app.js"],
            "forms": [{"action": "/upload", "method": "POST", "selector": "#upload", "inputTypes": [{"type": "file", "name": "file"}], "text": "upload"}],
            "pageText": "login password",
        },
    )

    result = scanner.scan("https://example.com", page_paths=["/"], protected_paths=["/dashboard"])

    assert result["status"] == "issues_found"
    assert "https://example.com/api/users" in result["discovered_endpoints"]
    assert result["openapi_specs"][0]["endpoint_count"] == 2
    assert any(issue["evidence"]["rule_id"] == "cors-reflected-origin" for issue in result["issues"])
    assert any(issue["evidence"]["rule_id"] == "upload-form-detected" for issue in result["issues"])
    assert any(issue["evidence"]["rule_id"] == "protected-path-public" for issue in result["issues"])


def test_app_controls_skips_auth_hardening_for_static_site(monkeypatch):
    scanner = AppControlsScanner()
    monkeypatch.setattr(scanner, "_extract_js_endpoints", lambda base_url, scripts: ([], []))
    monkeypatch.setattr(scanner, "_discover_openapi", lambda base_url: ([], []))
    monkeypatch.setattr(scanner, "_check_cors", lambda endpoints: [])
    monkeypatch.setattr(scanner, "_discover_common_surface", lambda *args, **kwargs: [])
    monkeypatch.setattr(scanner, "_check_protected_paths", lambda *args, **kwargs: [])
    monkeypatch.setattr(scanner, "_check_enumeration", lambda *args, **kwargs: [])
    monkeypatch.setattr(scanner, "_check_idor_templates", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        scanner,
        "_rendered_surface",
        lambda page_url: {
            "scripts": [],
            "forms": [],
            "pageText": "portfolio projects case studies contact resume",
        },
    )

    result = scanner.scan("https://example.com", page_paths=["/"])

    assert result["status"] == "ok"
    assert result["app_classification"]["auth_surface_detected"] is False
    assert result["app_classification"]["account_creation_surface_detected"] is False
    assert {item["control"] for item in result["skipped_controls"]} == {
        "mfa-signal",
        "email-verification-signal",
    }
    assert not any(issue["evidence"]["rule_id"] == "mfa-signal-missing" for issue in result["issues"])
    assert not any(issue["evidence"]["rule_id"] == "email-verification-signal-missing" for issue in result["issues"])


def test_app_controls_flags_auth_hardening_when_signup_surface_exists(monkeypatch):
    scanner = AppControlsScanner()
    monkeypatch.setattr(scanner, "_extract_js_endpoints", lambda base_url, scripts: (["https://example.com/api/signup"], []))
    monkeypatch.setattr(scanner, "_discover_openapi", lambda base_url: ([], []))
    monkeypatch.setattr(scanner, "_check_cors", lambda endpoints: [])
    monkeypatch.setattr(scanner, "_discover_common_surface", lambda *args, **kwargs: [])
    monkeypatch.setattr(scanner, "_check_protected_paths", lambda *args, **kwargs: [])
    monkeypatch.setattr(scanner, "_check_enumeration", lambda *args, **kwargs: [])
    monkeypatch.setattr(scanner, "_check_idor_templates", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        scanner,
        "_rendered_surface",
        lambda page_url: {
            "scripts": ["https://example.com/app.js"],
            "forms": [{
                "action": "/signup",
                "method": "POST",
                "selector": "#signup",
                "inputTypes": [{"type": "password", "name": "password"}],
                "text": "create account password",
            }],
            "pageText": "create account email password",
        },
    )

    result = scanner.scan("https://example.com", page_paths=["/"])

    assert result["status"] == "issues_found"
    assert result["app_classification"]["auth_surface_detected"] is True
    assert result["app_classification"]["account_creation_surface_detected"] is True
    assert any(issue["evidence"]["rule_id"] == "mfa-signal-missing" for issue in result["issues"])
    assert any(issue["evidence"]["rule_id"] == "email-verification-signal-missing" for issue in result["issues"])


def test_app_controls_flow_into_summary_and_sections():
    findings = {
        "app_controls": {
            "status": "issues_found",
            "issues": [
                {
                    "title": "Protected path is reachable without authentication",
                    "severity": "high",
                    "confidence": "measured",
                    "evidence": {"description": "/dashboard returned HTTP 200."},
                }
            ],
            "score": 92,
        }
    }

    summary = build_scan_summary(findings)
    sections = build_scan_sections(findings)

    assert summary["app_control_issue_count"] == 1
    assert summary["app_control_score"] == 92
    assert summary["launch_blocker_count"] == 1
    assert sections["app_controls"]["issue_count"] == 1
