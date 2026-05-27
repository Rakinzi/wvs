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
              const fcp = paints.find((e) => e.name === 'first-contentful-paint');
              const resources = performance.getEntriesByType('resource');

              // TTFB: time from navigationStart to first byte from server
              const ttfb = nav ? Math.round(nav.responseStart - nav.requestStart) : null;

              // TTI approximation: time until no long tasks for 5s window
              // We use domInteractive as a proxy since PerformanceLongTaskTiming
              // may not be available in all contexts.
              const tti = nav ? Math.round(nav.domInteractive) : null;

              // Transfer size breakdown
              let totalTransferBytes = 0;
              let jsTransferBytes = 0;
              let cssTransferBytes = 0;
              let imageTransferBytes = 0;
              let requestCount = resources.length;
              resources.forEach((r) => {
                const size = r.transferSize || 0;
                totalTransferBytes += size;
                const url = r.name || '';
                if (/\\.js(\\?|$)/.test(url)) jsTransferBytes += size;
                else if (/\\.css(\\?|$)/.test(url)) cssTransferBytes += size;
                else if (/\\.(png|jpe?g|gif|webp|avif|svg)(\\?|$)/i.test(url)) imageTransferBytes += size;
              });

              return {
                load_time_ms: nav ? Math.round(nav.loadEventEnd) : null,
                dom_content_loaded_ms: nav ? Math.round(nav.domContentLoadedEventEnd) : null,
                first_contentful_paint_ms: fcp ? Math.round(fcp.startTime) : null,
                ttfb_ms: ttfb,
                tti_ms: tti,
                resource_count: requestCount,
                total_transfer_kb: Math.round(totalTransferBytes / 1024),
                js_transfer_kb: Math.round(jsTransferBytes / 1024),
                css_transfer_kb: Math.round(cssTransferBytes / 1024),
                image_transfer_kb: Math.round(imageTransferBytes / 1024),
              };
            }
            """
        )

    def _findings_from_lighthouse(self, audit: dict[str, Any], page_url: str, screenshot_path: str) -> list[dict[str, Any]]:
        categories = audit.get("categories", {}) or {}
        audits = audit.get("audits", {}) or {}
        perf_score = int(round(((categories.get("performance") or {}).get("score") or 0) * 100))
        metrics = {
            "largest-contentful-paint":  (2500,  "Main content becomes visible too slowly (LCP)", "LCP"),
            "cumulative-layout-shift":   (0.1,   "Layout shifts are likely to disrupt reading or tapping (CLS)", "CLS"),
            "first-contentful-paint":    (1800,  "Initial content appears too slowly (FCP)", "FCP"),
            "total-blocking-time":       (200,   "Main thread blocking is likely to harm responsiveness (TBT)", "TBT"),
            "speed-index":               (3400,  "Page visually completes too slowly (Speed Index)", "Speed Index"),
            "interactive":               (3800,  "Page takes too long to become fully interactive (TTI)", "TTI"),
            "server-response-time":      (600,   "Server response time is too high (TTFB)", "TTFB"),
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

    def _issues_from_browser_metrics(self, metrics: dict[str, Any], page_url: str, screenshot_path: str) -> list[dict[str, Any]]:
        """Convert raw Navigation Timing / Resource Timing metrics into findings."""
        checks = [
            ("load_time_ms",              5000,  "slow-load",               "Page load time is too high",                      "medium",
             "load_time_ms",  "Load Time",
             "Visitors may perceive the product as slow before they understand its value.",
             "Compress media, reduce render-blocking scripts, and prioritize above-the-fold resources."),
            ("first_contentful_paint_ms", 1800,  "first-contentful-paint",  "Initial content appears too slowly (FCP)",         "medium",
             "FCP",           "FCP (ms)",
             "Users may feel the page is unresponsive before seeing useful content.",
             "Reduce critical-path work and prioritize the first visible content."),
            ("ttfb_ms",                   600,   "server-response-time",    "Server response time is too high (TTFB)",          "medium",
             "TTFB",          "TTFB (ms)",
             "A slow server response delays every subsequent resource and metric.",
             "Improve server-side caching, use a CDN, or reduce database query time."),
            ("tti_ms",                    3800,  "interactive",             "Page takes too long to become fully interactive (TTI)", "medium",
             "TTI",           "TTI (ms)",
             "Users cannot interact with the page reliably while it is still loading.",
             "Defer or split non-critical JavaScript to reduce main-thread work."),
            ("total_transfer_kb",         2000,  "transfer-size",           "Total page transfer size is too large",            "medium",
             "total_transfer_kb", "Transfer Size (KB)",
             "Large pages consume mobile data budgets and load slowly on slow connections.",
             "Compress assets, enable Brotli/gzip, lazy-load images, and code-split JavaScript."),
            ("js_transfer_kb",            500,   "js-transfer-size",        "JavaScript bundle size is too large",              "medium",
             "js_transfer_kb", "JS Size (KB)",
             "Large JavaScript bundles block the main thread and delay interactivity.",
             "Tree-shake unused code, split bundles, and defer non-critical scripts."),
        ]
        issues: list[dict[str, Any]] = []
        for field, threshold, rule_id, title, severity, metric_key, metric_label, user_impact, remediation in checks:
            value = metrics.get(field)
            if value is None or value <= threshold:
                continue
            issue = ux_finding_defaults(
                "performance_ux", "Performance UX", page_url, "mobile",
                title=title, severity=severity, confidence="measured",
                evidence={
                    "rule_id": rule_id,
                    "description": f"{metric_label} was {value} (threshold: {threshold}).",
                    "metric": metric_key,
                    "value": value,
                    "threshold": threshold,
                    "screenshot_path": screenshot_path,
                },
                user_impact=user_impact,
                technical_remediation=remediation,
            )
            issue["builder_prompt"] = build_builder_prompt(issue)
            issues.append(issue)
        return issues

    def scan(self, url: str, page_paths: list[str] | None = None) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        raw_metrics_by_page: dict[str, Any] = {}
        pages = build_page_targets(url, page_paths)[:3]

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(viewport={"width": settings.ux_scan_mobile_width, "height": settings.ux_scan_mobile_height})
                page = context.new_page()
                for page_url in pages:
                    page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                    screenshot_path = capture_page_screenshot(page, page_url, "mobile")

                    # Always collect raw timing metrics — used both for findings and
                    # as baseline data surfaced in the report regardless of Lighthouse.
                    metrics = self._browser_metrics(page)
                    raw_metrics_by_page[page_url] = metrics

                    lighthouse_payload = self._run_lighthouse(page_url)
                    if lighthouse_payload:
                        issues.extend(self._findings_from_lighthouse(lighthouse_payload, page_url, screenshot_path))
                        # Also check raw metrics that Lighthouse doesn't cover
                        # (transfer size, resource count) even when LH succeeds.
                        for field in ("total_transfer_kb", "js_transfer_kb"):
                            issues.extend(
                                i for i in self._issues_from_browser_metrics({field: metrics.get(field)}, page_url, screenshot_path)
                                if i
                            )
                    else:
                        issues.extend(self._issues_from_browser_metrics(metrics, page_url, screenshot_path))
            finally:
                browser.close()

        normalized = normalize_ux_findings(issues, default_scanner="performance_ux", default_category="Performance UX")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "raw_metrics": raw_metrics_by_page,
            "recommendations": [
                "Use Lighthouse for repeatable mobile performance budgets in release readiness checks when available.",
                "Optimize largest above-the-fold assets and reduce render-blocking JavaScript.",
                "Re-run performance checks after each major design or dependency change.",
            ] if normalized else [],
            "score": max(0, 100 - (len(normalized) * 10)),
        }
