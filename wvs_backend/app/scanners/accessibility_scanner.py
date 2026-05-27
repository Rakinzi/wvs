from __future__ import annotations

from pathlib import Path
from typing import Any

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from app.settings import settings
from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.ux_scan_helpers import DEFAULT_VIEWPORTS, build_page_targets, ux_finding_defaults
from app.utils.ux_screenshot_manager import capture_page_screenshot


_AXE_ASSET = Path(__file__).resolve().parents[1] / "assets" / "axe.min.js"
_AXE_IMPACT_TO_SEVERITY = {
    "critical": "critical",
    "serious": "high",
    "moderate": "medium",
    "minor": "low",
}


class AccessibilityScanner:
    def __init__(self, timeout_seconds: int | None = None):
        self.timeout_ms = (timeout_seconds or settings.ux_scan_page_timeout_seconds) * 1000

    def _map_axe_violation(self, violation: dict[str, Any], node: dict[str, Any], page_url: str, viewport_name: str, screenshot_path: str) -> dict[str, Any]:
        selector = ((node.get("target") or [None])[0]) if isinstance(node.get("target"), list) else None
        description = node.get("failureSummary") or violation.get("description") or ""
        title = violation.get("help") or violation.get("id") or "Accessibility issue"
        issue = ux_finding_defaults(
            "accessibility",
            "Accessibility",
            page_url,
            viewport_name,
            title=title,
            severity=_AXE_IMPACT_TO_SEVERITY.get(str(violation.get("impact") or "").lower(), "medium"),
            confidence="measured",
            selector=selector,
            evidence={
                "rule_id": violation.get("id"),
                "description": description,
                "screenshot_path": screenshot_path,
            },
            user_impact="Assistive technology users may not be able to understand or complete core tasks reliably.",
            technical_remediation=description or "Adjust the page so the affected control or structure meets accessibility requirements.",
            references=[],
        )
        issue["builder_prompt"] = build_builder_prompt(issue)
        return issue

    def scan(self, url: str, page_paths: list[str] | None = None) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        recommendations: list[str] = []
        pages = build_page_targets(url, page_paths)
        # Track axe rule+selector pairs already reported (desktop pass) so we
        # don't double-report the same structural issue on the mobile viewport.
        _axe_seen: set[tuple[str, str]] = set()

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                for page_url in pages:
                    for viewport_name, viewport in DEFAULT_VIEWPORTS.items():
                        context = browser.new_context(viewport=viewport)
                        page = context.new_page()
                        try:
                            page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                            # Let animations/transitions settle before measuring so
                            # elements that animate in don't register as inaccessible
                            # while they are mid-transition.
                            page.wait_for_timeout(1200)
                            page.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
                            page.add_script_tag(path=str(_AXE_ASSET))
                            screenshot_path = capture_page_screenshot(page, page_url, viewport_name)
                            axe_results = page.evaluate("() => window.axe.run()")
                            for violation in axe_results.get("violations", []):
                                rule_id = violation.get("id") or ""
                                for node in violation.get("nodes", [])[:10]:
                                    selector = ((node.get("target") or [None])[0]) if isinstance(node.get("target"), list) else ""
                                    dedup_key = (rule_id, str(selector))
                                    if dedup_key in _axe_seen:
                                        continue
                                    _axe_seen.add(dedup_key)
                                    issues.append(self._map_axe_violation(violation, node, page_url, viewport_name, screenshot_path))

                            keyboard_check = page.evaluate(
                                """
                                () => {
                                  const focusables = Array.from(document.querySelectorAll('a[href], button, input, textarea, select, [tabindex]'))
                                    .filter((el) => {
                                      const style = window.getComputedStyle(el);
                                      const rect = el.getBoundingClientRect();
                                      return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
                                    });
                                  return { count: focusables.length };
                                }
                                """
                            )
                            if keyboard_check.get("count"):
                                start_focus = page.evaluate("() => document.activeElement ? document.activeElement.tagName : null")
                                page.keyboard.press("Tab")
                                end_focus = page.evaluate("() => document.activeElement ? document.activeElement.tagName : null")
                                if start_focus == end_focus:
                                    dedup_key = ("keyboard-focus-basic", page_url)
                                    if dedup_key not in _axe_seen:
                                        _axe_seen.add(dedup_key)
                                        issue = ux_finding_defaults(
                                            "accessibility",
                                            "Accessibility",
                                            page_url,
                                            viewport_name,
                                            title="Keyboard focus did not move during a basic Tab navigation check",
                                            severity="medium",
                                            confidence="measured",
                                            evidence={
                                                "rule_id": "keyboard-focus-basic",
                                                "description": "A basic Tab-navigation check did not move visible focus to a new control.",
                                                "screenshot_path": screenshot_path,
                                            },
                                            user_impact="Keyboard-only users may struggle to reach visible controls.",
                                            technical_remediation="Ensure visible interactive controls are keyboard-focusable and that focus styles remain visible.",
                                        )
                                        issue["builder_prompt"] = build_builder_prompt(issue)
                                        issues.append(issue)

                            if viewport_name == "mobile":
                                measured = page.evaluate(
                                    """
                                    () => {
                                      const MIN = 44; // WCAG 2.5.5 recommended minimum
                                      return Array.from(document.querySelectorAll('button, a[href], input[type="submit"], input[type="button"], [role="button"]'))
                                        .map((el, index) => {
                                          const style = window.getComputedStyle(el);
                                          const rect = el.getBoundingClientRect();
                                          // Must be rendered and visible
                                          if (
                                            style.visibility === 'hidden' ||
                                            style.display === 'none' ||
                                            style.opacity === '0' ||
                                            rect.width <= 0 || rect.height <= 0
                                          ) return null;
                                          // Skip fixed/sticky elements (nav bars, FABs) — they are
                                          // intentionally positioned and not a layout concern.
                                          if (style.position === 'fixed' || style.position === 'sticky') return null;
                                          // Skip elements whose parent interactive element is large
                                          // enough — e.g. a <span> inside a big <a> or <button>.
                                          const parent = el.closest('a, button, [role="button"]');
                                          if (parent && parent !== el) {
                                            const pr = parent.getBoundingClientRect();
                                            if (pr.width >= MIN && pr.height >= MIN) return null;
                                          }
                                          // Flag only when BOTH dimensions are below the minimum
                                          // (avoids flagging intentionally narrow pill badges).
                                          if (rect.width < MIN && rect.height < MIN) {
                                            return {
                                              selector: el.id
                                                ? `#${el.id}`
                                                : `${el.tagName.toLowerCase()}:nth-of-type(${index + 1})`,
                                              width: Math.round(rect.width),
                                              height: Math.round(rect.height),
                                            };
                                          }
                                          return null;
                                        })
                                        .filter(Boolean);
                                    }
                                    """
                                )
                                for raw in measured:
                                    issue = ux_finding_defaults(
                                        "accessibility",
                                        "Mobile Accessibility",
                                        page_url,
                                        viewport_name,
                                        title="Tap target is too small on mobile",
                                        severity="medium",
                                        confidence="measured",
                                        selector=raw.get("selector"),
                                        evidence={
                                            "rule_id": "tap-target-size",
                                            "description": f"Interactive target is {raw.get('width')}×{raw.get('height')}px — below the 44×44px minimum.",
                                            "screenshot_path": screenshot_path,
                                        },
                                        user_impact="Touch users may struggle to activate the control reliably.",
                                        technical_remediation="Increase target size or spacing so controls are easier to tap on narrow screens.",
                                    )
                                    issue["builder_prompt"] = build_builder_prompt(issue)
                                    issues.append(issue)
                        except PlaywrightTimeoutError:
                            issue = ux_finding_defaults(
                                "accessibility",
                                "Accessibility",
                                page_url,
                                viewport_name,
                                title="Page could not be evaluated for accessibility",
                                severity="medium",
                                confidence="measured",
                                evidence={"rule_id": "page-timeout", "description": "The page did not finish loading before the scan timed out."},
                                user_impact="Critical accessibility issues may be missed if the page cannot render.",
                                technical_remediation="Reduce blocking assets or fix page load errors so the page can be evaluated.",
                            )
                            issue["builder_prompt"] = build_builder_prompt(issue)
                            issues.append(issue)
                        finally:
                            context.close()
            finally:
                browser.close()

        if issues:
            recommendations.extend([
                "Run measured accessibility checks before each release candidate and treat missing labels on key flows as launch blockers.",
                "Ensure headings, labels, and focus states remain usable on both desktop and mobile viewports.",
                "Use explicit labeling and valid ARIA relationships instead of relying on placeholders or visual context.",
            ])

        normalized = normalize_ux_findings(issues, default_scanner="accessibility", default_category="Accessibility")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "recommendations": recommendations,
            "score": max(0, 100 - (len(normalized) * 6)),
        }
