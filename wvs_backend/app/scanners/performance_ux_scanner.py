from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from playwright.sync_api import sync_playwright

from app.settings import settings
from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.ux_scan_helpers import build_page_targets, ux_finding_defaults
from app.utils.ux_screenshot_manager import capture_page_screenshot


class PerformanceUXScanner:
    def __init__(self, timeout_seconds: int | None = None):
        self.timeout_ms = (timeout_seconds or settings.ux_scan_page_timeout_seconds) * 1000

    def _resolve_lighthouse_path(self) -> str | None:
        configured = settings.lighthouse_cli_path
        if configured:
            return configured
        return shutil.which("lighthouse")

    def _run_lighthouse(self, page_url: str) -> dict[str, Any] | None:
        if not settings.lighthouse_enabled:
            return None
        cli = self._resolve_lighthouse_path()
        if not cli:
            return None

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "lighthouse.json"
            command = [
                cli,
                page_url,
                "--quiet",
                "--chrome-flags=--headless=new --no-sandbox",
                "--output=json",
                f"--output-path={output_path}",
                "--only-categories=performance",
                "--preset=desktop",
            ]
            try:
                subprocess.run(
                    command,
                    check=True,
                    timeout=settings.lighthouse_timeout_seconds,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return json.loads(output_path.read_text())
            except Exception:
                return None

    def _browser_metrics(self, page) -> dict[str, Any]:
        return page.evaluate(
            """
            () => {
              const nav = performance.getEntriesByType('navigation')[0];
              const paints = performance.getEntriesByType('paint');
              const fcp = paints.find((entry) => entry.name === 'first-contentful-paint');
              return {
                load_time_ms: nav ? Math.round(nav.loadEventEnd) : null,
                dom_content_loaded_ms: nav ? Math.round(nav.domContentLoadedEventEnd) : null,
                first_contentful_paint_ms: fcp ? Math.round(fcp.startTime) : null,
                resource_count: performance.getEntriesByType('resource').length,
              };
            }
            """
        )

    def _findings_from_lighthouse(self, audit: dict[str, Any], page_url: str, screenshot_path: str) -> list[dict[str, Any]]:
        categories = audit.get("categories", {}) or {}
        audits = audit.get("audits", {}) or {}
        perf_score = int(round(((categories.get("performance") or {}).get("score") or 0) * 100))
        metrics = {
            "largest-contentful-paint": (2500, "Main content becomes visible too slowly on mobile", "LCP"),
            "cumulative-layout-shift": (0.1, "Layout shifts are likely to disrupt reading or tapping", "CLS"),
            "first-contentful-paint": (1800, "Initial content appears too slowly", "FCP"),
            "total-blocking-time": (200, "Main thread blocking is likely to harm responsiveness", "TBT"),
            "speed-index": (3400, "Page visually completes too slowly", "Speed Index"),
        }
        issues: list[dict[str, Any]] = []
        for audit_key, (threshold, title, metric_label) in metrics.items():
            payload = audits.get(audit_key) or {}
            numeric = payload.get("numericValue")
            if numeric is None:
                continue
            if float(numeric) <= float(threshold):
                continue
            issue = ux_finding_defaults(
                "performance_ux",
                "Performance UX",
                page_url,
                "mobile",
                title=title,
                severity="medium" if audit_key != "total-blocking-time" else "high",
                confidence="measured",
                evidence={
                    "rule_id": audit_key,
                    "description": payload.get("description") or payload.get("title") or "",
                    "metric": metric_label,
                    "value": round(float(numeric), 2),
                    "threshold": threshold,
                    "screenshot_path": screenshot_path,
                },
                user_impact="Visitors may perceive the app as slow or unstable before they understand its value.",
                technical_remediation="Reduce blocking resources, optimize above-the-fold assets, and trim expensive scripts.",
            )
            issue["builder_prompt"] = build_builder_prompt(issue)
            issues.append(issue)

        opportunities = [
            audits.get("unused-javascript"),
            audits.get("render-blocking-resources"),
            audits.get("uses-optimized-images"),
        ]
        for opportunity in opportunities:
            if not isinstance(opportunity, dict):
                continue
            if (opportunity.get("score") or 1) >= 0.9:
                continue
            issue = ux_finding_defaults(
                "performance_ux",
                "Performance UX",
                page_url,
                "mobile",
                title=opportunity.get("title") or "Performance optimization opportunity detected",
                severity="low",
                confidence="measured",
                evidence={
                    "rule_id": opportunity.get("id") or "lighthouse-opportunity",
                    "description": opportunity.get("description") or "",
                    "screenshot_path": screenshot_path,
                },
                user_impact="Resource inefficiencies can slow down first impressions on mobile networks.",
                technical_remediation=opportunity.get("description") or "Optimize this resource pattern before launch.",
            )
            issue["builder_prompt"] = build_builder_prompt(issue)
            issues.append(issue)

        if perf_score and perf_score < 60:
            issue = ux_finding_defaults(
                "performance_ux",
                "Performance UX",
                page_url,
                "mobile",
                title="Overall Lighthouse performance score is below the recommended launch threshold",
                severity="high",
                confidence="measured",
                evidence={
                    "rule_id": "lighthouse-performance-score",
                    "description": "The Lighthouse performance score fell below the recommended threshold.",
                    "metric": "performance_score",
                    "value": perf_score,
                    "threshold": 60,
                    "screenshot_path": screenshot_path,
                },
                user_impact="The experience may feel slow enough to damage trust and increase drop-off on first visit.",
                technical_remediation="Reduce the page's largest bottlenecks before launch and re-run the audit to confirm improvement.",
            )
            issue["builder_prompt"] = build_builder_prompt(issue)
            issues.append(issue)

        return issues

    def scan(self, url: str, page_paths: list[str] | None = None) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        pages = build_page_targets(url, page_paths)[:3]

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(viewport={"width": settings.ux_scan_mobile_width, "height": settings.ux_scan_mobile_height})
                page = context.new_page()
                for page_url in pages:
                    page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                    screenshot_path = capture_page_screenshot(page, page_url, "mobile")
                    lighthouse_payload = self._run_lighthouse(page_url)
                    if lighthouse_payload:
                        issues.extend(self._findings_from_lighthouse(lighthouse_payload, page_url, screenshot_path))
                        continue

                    metrics = self._browser_metrics(page)
                    if metrics.get("load_time_ms") and metrics["load_time_ms"] > 5000:
                        issue = ux_finding_defaults(
                            "performance_ux",
                            "Performance UX",
                            page_url,
                            "mobile",
                            title="Main content becomes visible too slowly on mobile",
                            severity="medium",
                            confidence="measured",
                            evidence={
                                "rule_id": "slow-load",
                                "description": "Navigation load time exceeded 5000ms.",
                                "metric": "load_time_ms",
                                "value": metrics["load_time_ms"],
                                "threshold": 5000,
                                "screenshot_path": screenshot_path,
                            },
                            user_impact="Visitors may perceive the product as slow before they understand its value.",
                            technical_remediation="Compress media, reduce render-blocking scripts, and prioritize above-the-fold resources.",
                        )
                        issue["builder_prompt"] = build_builder_prompt(issue)
                        issues.append(issue)
                    if metrics.get("first_contentful_paint_ms") and metrics["first_contentful_paint_ms"] > 1800:
                        issue = ux_finding_defaults(
                            "performance_ux",
                            "Performance UX",
                            page_url,
                            "mobile",
                            title="Initial content appears too slowly",
                            severity="medium",
                            confidence="measured",
                            evidence={
                                "rule_id": "first-contentful-paint",
                                "description": "First Contentful Paint exceeded 1800ms.",
                                "metric": "FCP",
                                "value": metrics["first_contentful_paint_ms"],
                                "threshold": 1800,
                                "screenshot_path": screenshot_path,
                            },
                            user_impact="Users may feel the page is unresponsive before seeing useful content.",
                            technical_remediation="Reduce critical-path work and prioritize the first visible content.",
                        )
                        issue["builder_prompt"] = build_builder_prompt(issue)
                        issues.append(issue)
            finally:
                browser.close()

        normalized = normalize_ux_findings(issues, default_scanner="performance_ux", default_category="Performance UX")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "recommendations": [
                "Use Lighthouse for repeatable mobile performance budgets in release readiness checks when available.",
                "Optimize largest above-the-fold assets and reduce render-blocking JavaScript.",
                "Re-run performance checks after each major design or dependency change.",
            ] if normalized else [],
            "score": max(0, 100 - (len(normalized) * 10)),
        }
