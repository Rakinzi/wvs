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


def _node_element_summary(node: dict[str, Any]) -> str:
    return str(node.get("elementSummary") or "").strip()


def _node_text(node: dict[str, Any]) -> str:
    element = node.get("element") if isinstance(node.get("element"), dict) else {}
    return str(element.get("text") or "").strip()


def _attrs(node: dict[str, Any]) -> dict[str, Any]:
    element = node.get("element") if isinstance(node.get("element"), dict) else {}
    attrs = element.get("attributes") if isinstance(element.get("attributes"), dict) else {}
    return attrs


def _selector_from_node(node: dict[str, Any]) -> str:
    target = node.get("target")
    if isinstance(target, list) and target:
        return str(target[0] or "")
    return ""


def _specific_accessibility_text(rule_id: str, title: str, description: str, node: dict[str, Any]) -> tuple[str, str, str]:
    summary = _node_element_summary(node) or "The affected element"
    selector = _selector_from_node(node)
    selector_text = f" ({selector})" if selector else ""
    text = _node_text(node)
    attrs = _attrs(node)

    if rule_id == "label":
        label_target = attrs.get("id") or attrs.get("name") or selector
        label_hint = (
            f"Add a visible label for this field. In code, connect it with <label for=\"{label_target}\">...</label>, or use aria-labelledby when the label text already exists on the page."
            if label_target
            else "Add a visible label for this field. If the visual design cannot show a label, add a clear aria-label that explains what the field is for."
        )
        return (
            f"The field {summary}{selector_text} is missing a readable label. Someone using a screen reader or voice control may only hear a vague control name instead of knowing what to enter.",
            "People using screen readers, voice control, or translation tools may not understand what this field is asking for.",
            label_hint,
        )

    if rule_id == "button-name":
        visible_text = " It does not contain visible text." if not text else f" Its visible text is currently '{text}'."
        return (
            f"The interactive control {summary}{selector_text} does not have a clear name.{visible_text} A user may not know whether it opens a menu, views a product, removes an item, or performs another action.",
            "People using screen readers or voice commands need every link and button to have a clear action name.",
            "Give the control a short action label. Prefer visible text when possible; otherwise add aria-label or aria-labelledby, such as 'Open menu', 'View product', or 'Remove item'.",
        )

    if rule_id == "heading-order":
        heading_text = f" The heading text is '{text}'." if text else ""
        return (
            f"The heading {summary}{selector_text} appears out of order. {description}{heading_text}",
            "People who navigate by headings may lose the page structure or miss important sections.",
            "Keep heading levels in sequence, like H1, H2, then H3. Change the affected heading to the next logical level, or add the missing section heading above it.",
        )

    if rule_id == "image-alt":
        return (
            f"The visible image {summary}{selector_text} does not have alternative text.",
            "People who cannot see the image may miss important product, navigation, or context information.",
            "Add short alt text that describes the image's purpose. If the image is only decorative, use an empty alt attribute so assistive tools skip it.",
        )

    if rule_id == "duplicate-id":
        duplicate_id = attrs.get("id")
        return (
            f"The element {summary}{selector_text} reuses the id '{duplicate_id}', which should be unique on the page.",
            "Duplicate IDs can make labels, error messages, and in-page links point to the wrong element.",
            "Give this element a unique id and update any label, aria-labelledby, aria-describedby, or link that points to it.",
        )

    if rule_id == "frame-title":
        return (
            f"The embedded frame {summary}{selector_text} does not have a title.",
            "People using assistive tools may not know what content or service is inside the embedded frame.",
            "Add a short title that explains the embedded content, such as 'Payment form', 'Map', or 'Product video'.",
        )

    if rule_id == "html-lang":
        return (
            "The page does not declare its main language.",
            "Screen readers and translation tools may choose the wrong pronunciation or language rules.",
            "Set the language on the html element, for example <html lang=\"en\">.",
        )

    return (
        f"The element {summary}{selector_text} needs an accessibility fix: {description or title}",
        "Some users may not be able to understand or complete this part of the page reliably.",
        description or "Adjust the affected control or page structure so it is understandable and usable with assistive tools.",
    )


class AccessibilityScanner:
    def __init__(self, timeout_seconds: int | None = None):
        self.timeout_ms = (timeout_seconds or settings.ux_scan_page_timeout_seconds) * 1000

    def _map_axe_violation(self, violation: dict[str, Any], node: dict[str, Any], page_url: str, viewport_name: str, screenshot_path: str) -> dict[str, Any]:
        selector = ((node.get("target") or [None])[0]) if isinstance(node.get("target"), list) else None
        description = node.get("failureSummary") or violation.get("description") or ""
        title = violation.get("help") or violation.get("id") or "Accessibility issue"
        rule_id = str(violation.get("id") or "")
        evidence_description, user_impact, remediation = _specific_accessibility_text(rule_id, title, description, node)
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
                "rule_id": rule_id,
                "description": evidence_description,
                "element": node.get("element") if isinstance(node.get("element"), dict) else {},
                "element_summary": _node_element_summary(node),
                "html": str(node.get("html") or ""),
                "screenshot_path": screenshot_path,
            },
            user_impact=user_impact,
            technical_remediation=remediation,
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
                                              selector: window.__launchGuardA11y?.selectorFor
                                                ? window.__launchGuardA11y.selectorFor(el)
                                                : (el.id ? `#${el.id}` : `${el.tagName.toLowerCase()}:nth-of-type(${index + 1})`),
                                              element: window.__launchGuardA11y?.elementDetails
                                                ? window.__launchGuardA11y.elementDetails(el)
                                                : { tag: el.tagName.toLowerCase(), attributes: {}, text: '' },
                                              elementSummary: window.__launchGuardA11y?.elementSummary
                                                ? window.__launchGuardA11y.elementSummary(el)
                                                : `<${el.tagName.toLowerCase()}>`,
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
                                    summary = str(raw.get("elementSummary") or "Interactive target").strip()
                                    selector = raw.get("selector")
                                    selector_text = f" at `{selector}`" if selector else ""
                                    width = raw.get("width")
                                    height = raw.get("height")
                                    issue = ux_finding_defaults(
                                        "accessibility",
                                        "Mobile Accessibility",
                                        page_url,
                                        viewport_name,
                                        title="Tap target is too small on mobile",
                                        severity="medium",
                                        confidence="measured",
                                        selector=selector,
                                        evidence={
                                            "rule_id": "tap-target-size",
                                            "description": f"{summary}{selector_text} is {width}×{height}px, below the 44×44px recommended mobile touch target.",
                                            "element": raw.get("element") if isinstance(raw.get("element"), dict) else {},
                                            "element_summary": summary,
                                            "screenshot_path": screenshot_path,
                                        },
                                        user_impact="Touch users may miss or accidentally activate nearby controls on narrow screens.",
                                        technical_remediation=f"Increase the tappable area for {summary} to at least 44×44px, or add spacing so adjacent controls are not crowded.",
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
