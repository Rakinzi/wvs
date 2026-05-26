from __future__ import annotations

from typing import Any

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.ux_scan_helpers import DEFAULT_VIEWPORTS, build_page_targets, ux_finding_defaults
from app.utils.ux_screenshot_manager import capture_page_screenshot


class ResponsiveScanner:
    def __init__(self, timeout_seconds: int = 20):
        self.timeout_ms = timeout_seconds * 1000

    def scan(self, url: str, page_paths: list[str] | None = None) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        pages = build_page_targets(url, page_paths)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                for page_url in pages:
                    for viewport_name, viewport in DEFAULT_VIEWPORTS.items():
                        context = browser.new_context(viewport=viewport)
                        page = context.new_page()
                        try:
                            page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                            screenshot_path = capture_page_screenshot(page, page_url, viewport_name)
                            measured = page.evaluate(
                                """
                                () => {
                                  const visible = (el) => {
                                    const style = window.getComputedStyle(el);
                                    const rect = el.getBoundingClientRect();
                                    return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
                                  };
                                  const selectorFor = (el, index) => el.id ? `#${el.id}` : `${el.tagName.toLowerCase()}:nth-of-type(${index + 1})`;
                                  const issues = [];
                                  if (document.documentElement.scrollWidth > window.innerWidth + 4) {
                                    issues.push({
                                      title: 'Horizontal overflow detected',
                                      severity: 'high',
                                      selector: 'html',
                                      rule_id: 'horizontal-overflow',
                                      description: `Document width ${document.documentElement.scrollWidth}px exceeds viewport width ${window.innerWidth}px.`,
                                      metric: 'scrollWidth',
                                      value: document.documentElement.scrollWidth,
                                      threshold: window.innerWidth,
                                      user_impact: 'Users may need to scroll sideways to access content or controls.',
                                      technical_remediation: 'Constrain wide content and ensure layouts wrap correctly on narrow screens.',
                                    });
                                  }
                                  document.querySelectorAll('button, a[href], input, textarea, select').forEach((el, index) => {
                                    if (!visible(el)) return;
                                    const rect = el.getBoundingClientRect();
                                    if (rect.right > window.innerWidth + 4 || rect.left < -4) {
                                      issues.push({
                                        title: 'Interactive element is partially off-screen',
                                        severity: 'high',
                                        selector: selectorFor(el, index),
                                        rule_id: 'off-screen-interactive',
                                        description: `Control bounds (${Math.round(rect.left)}, ${Math.round(rect.right)}) exceed viewport width ${window.innerWidth}px.`,
                                        user_impact: 'Users may not be able to reach or fully understand the control.',
                                        technical_remediation: 'Reflow the layout so interactive elements stay within the viewport.',
                                      });
                                    }
                                  });
                                  document.querySelectorAll('form').forEach((form, index) => {
                                    if (!visible(form)) return;
                                    const rect = form.getBoundingClientRect();
                                    if (rect.right > window.innerWidth + 4) {
                                      issues.push({
                                        title: 'Form layout is clipped on the current viewport',
                                        severity: 'high',
                                        selector: selectorFor(form, index),
                                        rule_id: 'clipped-form',
                                        description: `Form extends to ${Math.round(rect.right)}px on a ${window.innerWidth}px viewport.`,
                                        user_impact: 'Users may not be able to complete the form on this device size.',
                                        technical_remediation: 'Stack or resize form fields and actions so the form fits the viewport.',
                                      });
                                    }
                                  });
                                  return issues;
                                }
                                """
                            )
                            for raw in measured:
                                issue = ux_finding_defaults(
                                    "responsive_ux",
                                    "Mobile and Responsive UX",
                                    page_url,
                                    viewport_name,
                                    title=raw["title"],
                                    severity=raw["severity"],
                                    confidence="measured",
                                    selector=raw.get("selector"),
                                    evidence={
                                        "rule_id": raw.get("rule_id"),
                                        "description": raw.get("description"),
                                        "metric": raw.get("metric"),
                                        "value": raw.get("value"),
                                        "threshold": raw.get("threshold"),
                                    },
                                    user_impact=raw.get("user_impact"),
                                    technical_remediation=raw.get("technical_remediation"),
                                    references=[],
                                )
                                issue["evidence"]["screenshot_path"] = screenshot_path
                                issue["builder_prompt"] = build_builder_prompt(issue)
                                issues.append(issue)
                        except PlaywrightTimeoutError:
                            issue = ux_finding_defaults(
                                "responsive_ux",
                                "Mobile and Responsive UX",
                                page_url,
                                viewport_name,
                                title="Page could not be evaluated for responsive layout",
                                severity="medium",
                                confidence="measured",
                                evidence={"rule_id": "page-timeout", "description": "The page did not finish loading before the responsive scan timed out."},
                                user_impact="Layout defects may remain undetected on smaller viewports.",
                                technical_remediation="Reduce page load blockers so responsive checks can complete.",
                            )
                            issue["builder_prompt"] = build_builder_prompt(issue)
                            issues.append(issue)
                        finally:
                            context.close()
            finally:
                browser.close()

        normalized = normalize_ux_findings(issues, default_scanner="responsive_ux", default_category="Mobile and Responsive UX")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "recommendations": [
                "Test primary pages on 390px-wide screens before release.",
                "Avoid fixed-width layout primitives that can force horizontal scrolling.",
            ] if normalized else [],
            "score": max(0, 100 - (len(normalized) * 10)),
        }
