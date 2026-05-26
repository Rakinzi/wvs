from __future__ import annotations

from typing import Any

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from app.services.visual_ai_provider import build_visual_ai_provider
from app.settings import settings
from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.ux_scan_helpers import DEFAULT_VIEWPORTS, build_page_targets
from app.utils.ux_screenshot_manager import capture_page_screenshot


class VisualAIScanner:
    def __init__(self, timeout_seconds: int | None = None):
        self.timeout_ms = (timeout_seconds or settings.ux_scan_page_timeout_seconds) * 1000

    def scan(
        self,
        url: str,
        page_paths: list[str] | None = None,
        enabled: bool = False,
        page_type: str | None = None,
    ) -> dict[str, Any]:
        if not enabled:
            return {"status": "disabled", "issues": [], "recommendations": [], "score": None}

        provider = build_visual_ai_provider()
        if not provider.is_available():
            return {
                "status": "not_configured",
                "issues": [],
                "recommendations": ["AI visual review is enabled for this scan profile but no provider is configured yet."],
                "score": None,
            }

        issues: list[dict[str, Any]] = []
        pages = build_page_targets(url, page_paths)
        screenshot_budget = max(1, settings.visual_ai_max_screenshots_per_scan)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                for page_url in pages:
                    for viewport_name, viewport in DEFAULT_VIEWPORTS.items():
                        if screenshot_budget <= 0:
                            break
                        context = browser.new_context(viewport=viewport)
                        page = context.new_page()
                        try:
                            page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                            screenshot_path = capture_page_screenshot(page, page_url, viewport_name)
                            provider_findings = provider.analyse_page_screenshot(
                                screenshot_path,
                                page_url,
                                viewport_name,
                                page_type=page_type,
                            )
                            for item in provider_findings:
                                evidence = item.setdefault("evidence", {})
                                evidence["screenshot_path"] = screenshot_path
                                if not item.get("builder_prompt"):
                                    item["builder_prompt"] = build_builder_prompt(item)
                                issues.append(item)
                            screenshot_budget -= 1
                        except PlaywrightTimeoutError:
                            pass
                        finally:
                            context.close()
                    if screenshot_budget <= 0:
                        break
            finally:
                browser.close()

        normalized = normalize_ux_findings(
            issues,
            default_scanner="visual_ai",
            default_category="Visual UX",
        )
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "recommendations": [
                "Treat AI-assisted visual findings as advisory and confirm them with a human review before prioritizing design changes."
            ] if normalized else [],
            "score": None,
        }
