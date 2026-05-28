from __future__ import annotations

import requests

from app.scanners.broken_link_scanner import BrokenLinkScanner
from app.utils.scan_helpers import build_scan_sections, build_scan_summary


class FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code

    def close(self):
        return None


def test_broken_link_scanner_reports_failed_links(monkeypatch):
    scanner = BrokenLinkScanner()
    monkeypatch.setattr(
        scanner,
        "_extract_links",
        lambda page_url: [
            {"url": "https://example.com/missing", "text": "Missing", "selector": "a:nth-of-type(1)"},
            {"url": "https://external.example/dead", "text": "External", "selector": "a:nth-of-type(2)"},
        ],
    )
    monkeypatch.setattr(requests, "head", lambda url, **kwargs: FakeResponse(404 if "missing" in url else 200))

    result = scanner.scan("https://example.com", page_paths=["/"])

    assert result["status"] == "issues_found"
    assert len(result["issues"]) == 1
    assert result["issues"][0]["scanner"] == "broken_links"
    assert result["issues"][0]["severity"] == "medium"
    assert "https://example.com/missing" in result["issues"][0]["evidence"]["description"]


def test_broken_link_scanner_handles_request_errors(monkeypatch):
    scanner = BrokenLinkScanner()
    monkeypatch.setattr(
        scanner,
        "_extract_links",
        lambda page_url: [{"url": "https://external.example/dead", "text": "External", "selector": "a:nth-of-type(1)"}],
    )

    def raise_timeout(url, **kwargs):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(requests, "head", raise_timeout)

    result = scanner.scan("https://example.com", page_paths=["/"])

    assert result["status"] == "issues_found"
    assert result["issues"][0]["severity"] == "low"
    assert "Timeout" in result["issues"][0]["evidence"]["description"]


def test_broken_links_flow_into_summary_and_sections():
    findings = {
        "broken_links": {
            "status": "issues_found",
            "issues": [
                {
                    "title": "Broken link detected",
                    "severity": "medium",
                    "confidence": "measured",
                    "evidence": {"description": "Link target failed."},
                }
            ],
            "score": 92,
        }
    }

    summary = build_scan_summary(findings)
    sections = build_scan_sections(findings)

    assert summary["broken_link_issue_count"] == 1
    assert summary["broken_link_score"] == 92
    assert sections["broken_links"]["issue_count"] == 1
