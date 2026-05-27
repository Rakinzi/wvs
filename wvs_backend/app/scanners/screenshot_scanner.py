from __future__ import annotations

import logging
from typing import Any

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from app.settings import settings
from app.utils.ux_scan_helpers import DEFAULT_VIEWPORTS
from app.utils.ux_screenshot_manager import capture_page_screenshot

logger = logging.getLogger(__name__)


class ScreenshotScanner:
    """Captures desktop and mobile screenshots of a target URL during any scan."""

    def __init__(self, timeout_seconds: int | None = None):
        self.timeout_ms = (timeout_seconds or settings.ux_scan_page_timeout_seconds) * 1000

    def scan(self, url: str) -> dict[str, Any]:
        screenshots: dict[str, str] = {}

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    for viewport_name, viewport in DEFAULT_VIEWPORTS.items():
                        context = browser.new_context(
                            viewport=viewport,
                            user_agent=(
                                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
                                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
                                if viewport_name == "mobile"
                                else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                            ),
                        )
                        page = context.new_page()
                        try:
                            page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
                            path = capture_page_screenshot(page, url, viewport_name)
                            screenshots[viewport_name] = path
                        except PlaywrightTimeoutError:
                            logger.warning("Screenshot timeout for %s (%s)", url, viewport_name)
                        except Exception as exc:
                            logger.warning("Screenshot failed for %s (%s): %s", url, viewport_name, exc)
                        finally:
                            context.close()
                finally:
                    browser.close()
        except Exception as exc:
            logger.warning("Screenshot scanner failed for %s: %s", url, exc)

        return {
            "status": "captured" if screenshots else "failed",
            "screenshots": screenshots,
        }
