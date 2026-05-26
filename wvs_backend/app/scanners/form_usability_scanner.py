from __future__ import annotations

from typing import Any

from playwright.sync_api import sync_playwright

from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.ux_scan_helpers import build_page_targets, ux_finding_defaults
from app.utils.ux_screenshot_manager import capture_page_screenshot


class FormUsabilityScanner:
    def __init__(self, timeout_seconds: int = 20):
        self.timeout_ms = timeout_seconds * 1000

    def scan(self, url: str, page_paths: list[str] | None = None) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        pages = build_page_targets(url, page_paths)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(viewport={"width": 390, "height": 844})
                page = context.new_page()
                for page_url in pages:
                    page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                    screenshot_path = capture_page_screenshot(page, page_url, "mobile")
                    measured = page.evaluate(
                        """
                        () => {
                          const visible = (el) => {
                            const style = window.getComputedStyle(el);
                            const rect = el.getBoundingClientRect();
                            return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
                          };
                          const issues = [];
                          document.querySelectorAll('form').forEach((form, index) => {
                            if (!visible(form)) return;
                            const required = form.querySelectorAll('input[required], textarea[required], select[required]');
                            if (required.length > 0) {
                              const unlabeled = Array.from(required).filter((field) => !field.labels?.length && !field.getAttribute('aria-label'));
                              if (unlabeled.length > 0) {
                                issues.push({
                                  title: 'Required form fields are not clearly labeled',
                                  severity: 'medium',
                                  selector: form.id ? `#${form.id}` : `form:nth-of-type(${index + 1})`,
                                  rule_id: 'required-labels',
                                  description: `${unlabeled.length} required field(s) are missing explicit labels.`,
                                  user_impact: 'Users may not understand what is required before submitting the form.',
                                  technical_remediation: 'Add clear visible labels and indicate required fields consistently.',
                                });
                              }
                            }
                            const submit = form.querySelector('button[type="submit"], input[type="submit"]');
                            if (!submit || !visible(submit)) {
                              issues.push({
                                title: 'Visible form is missing an obvious submit action',
                                severity: 'high',
                                selector: form.id ? `#${form.id}` : `form:nth-of-type(${index + 1})`,
                                rule_id: 'missing-submit',
                                description: 'A visible form does not expose a visible submit control.',
                                user_impact: 'Users may be unable to complete the primary workflow.',
                                technical_remediation: 'Expose a clear primary submit action within the form viewport.',
                              });
                            }
                          });
                          return issues;
                        }
                        """
                    )
                    for raw in measured:
                        issue = ux_finding_defaults(
                            "form_usability",
                            "Form and Interaction Usability",
                            page_url,
                            "mobile",
                            title=raw["title"],
                            severity=raw["severity"],
                            confidence="heuristic",
                            selector=raw.get("selector"),
                            evidence={"rule_id": raw.get("rule_id"), "description": raw.get("description")},
                            user_impact=raw.get("user_impact"),
                            technical_remediation=raw.get("technical_remediation"),
                            references=[],
                        )
                        issue["evidence"]["screenshot_path"] = screenshot_path
                        issue["builder_prompt"] = build_builder_prompt(issue)
                        issues.append(issue)
            finally:
                browser.close()

        normalized = normalize_ux_findings(issues, default_scanner="form_usability", default_category="Form and Interaction Usability")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "recommendations": [
                "Keep primary forms simple on mobile and make submit actions prominent.",
                "Pair validation and required-state messaging with the exact affected field.",
            ] if normalized else [],
            "score": max(0, 100 - (len(normalized) * 10)),
        }
