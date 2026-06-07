from __future__ import annotations

import httpx

from app.scanners import exposure_scanner as exposure_module
from app.scanners.exposure_scanner import ExposureScanner


class FakeExposureClient:
    def get(self, url):
        request = httpx.Request("GET", url)
        if url.endswith("/terraform.tfvars"):
            return httpx.Response(
                200,
                text='db_password = "redacted-example"\nregion = "us-east-1"\n',
                headers={"content-type": "text/plain"},
                request=request,
            )
        return httpx.Response(
            200,
            text="<html><body>Portfolio fallback page</body></html>",
            headers={"content-type": "text/html"},
            request=request,
        )

    def close(self):
        return None


class FakeSpaFallbackClient:
    fallback = """<!doctype html>
    <html><head><meta charset="utf-8"><script defer="defer" src="/assets/app.js"></script></head>
    <body><div id="root"></div></body></html>"""

    def get(self, url):
        return httpx.Response(
            200,
            text=self.fallback,
            headers={"content-type": "text/html"},
            request=httpx.Request("GET", url),
        )


def test_exposure_scanner_adds_verification_metadata_and_rejects_soft_404(monkeypatch):
    monkeypatch.setattr(
        exposure_module,
        "SENSITIVE_PATHS",
        [
            {
                "path": "/terraform.tfvars",
                "severity": "Critical",
                "name": "Terraform vars exposed",
                "stack": "devops",
            },
            {
                "path": "/config/database.yml",
                "severity": "Critical",
                "name": "Database config exposed",
                "stack": "ruby",
            },
        ],
    )
    scanner = ExposureScanner()
    scanner.client = FakeExposureClient()
    monkeypatch.setattr(exposure_module.settings, "external_tools_enabled", False)

    result = scanner.scan("https://example.com")

    assert len(result["issues"]) == 1
    issue = result["issues"][0]
    assert issue["path"] == "/terraform.tfvars"
    assert issue["status_code"] == 200
    assert issue["content_type"] == "text/plain"
    assert issue["confidence"] == "high"
    assert issue["matched_content_signal"] is True
    assert issue["manual_verification_required"] is True
    assert "expected content signature" in issue["detection_reason"]


def test_exposure_scanner_rejects_spa_fallback_for_tfvars_and_logs(monkeypatch):
    monkeypatch.setattr(
        exposure_module,
        "SENSITIVE_PATHS",
        [
            {
                "path": "/terraform.tfvars",
                "severity": "Critical",
                "name": "Terraform vars exposed",
                "stack": "devops",
            },
            {
                "path": "/error.log",
                "severity": "Medium",
                "name": "Error log exposed",
                "stack": "universal",
            },
        ],
    )
    scanner = ExposureScanner()
    scanner.client = FakeSpaFallbackClient()
    monkeypatch.setattr(exposure_module.settings, "external_tools_enabled", False)

    result = scanner.scan("https://example.com")

    assert result["status"] == "ok"
    assert result["issues"] == []
