from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from app.settings import settings
from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.ux_scan_helpers import build_page_targets, ux_finding_defaults


class BrokenLinkScanner:
    def __init__(self, timeout_seconds: int | None = None):
        self.timeout_ms = (timeout_seconds or settings.ux_scan_page_timeout_seconds) * 1000
        self.http_timeout = timeout_seconds or settings.broken_link_timeout_seconds

    def _same_origin(self, source_url: str, candidate_url: str) -> bool:
        source = urlparse(source_url)
        candidate = urlparse(candidate_url)
        return source.scheme == candidate.scheme and source.netloc == candidate.netloc

    def _normalize_link(self, page_url: str, href: str) -> str | None:
        raw = str(href or "").strip()
        if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:", "blob:")):
            return None
        candidate = urljoin(page_url, raw)
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        return candidate

    def _extract_links(self, page_url: str) -> list[dict[str, str]]:
        links: list[dict[str, str]] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                raw_links = page.evaluate(
                    """
                    () => Array.from(document.querySelectorAll('a[href]')).map((el, index) => ({
                      href: el.getAttribute('href') || '',
                      absolute: el.href || '',
                      text: (el.textContent || '').trim().slice(0, 120),
                      selector: el.id ? `#${el.id}` : `a:nth-of-type(${index + 1})`,
                    }))
                    """
                )
                seen: set[str] = set()
                for item in raw_links:
                    target = self._normalize_link(page_url, item.get("absolute") or item.get("href"))
                    if not target or target in seen:
                        continue
                    seen.add(target)
                    links.append({
                        "url": target,
                        "text": str(item.get("text") or ""),
                        "selector": str(item.get("selector") or ""),
                    })
                    if len(links) >= settings.broken_link_max_links_per_page:
                        break
            finally:
                browser.close()
        return links

    def _check_link(self, url: str) -> tuple[bool, int | None, str]:
        try:
            response = requests.head(
                url,
                timeout=self.http_timeout,
                allow_redirects=True,
                headers={"User-Agent": "WVS-BrokenLinkScanner/1.0"},
            )
            if response.status_code in {405, 403} or response.status_code >= 500:
                response = requests.get(
                    url,
                    timeout=self.http_timeout,
                    allow_redirects=True,
                    stream=True,
                    headers={"User-Agent": "WVS-BrokenLinkScanner/1.0"},
                )
                response.close()
            if response.status_code >= 400:
                return False, response.status_code, f"HTTP {response.status_code}"
            return True, response.status_code, "OK"
        except requests.RequestException as exc:
            return False, None, type(exc).__name__

    def _issue(self, page_url: str, link: dict[str, str], status_code: int | None, reason: str) -> dict[str, Any]:
        target = link["url"]
        severity = "medium" if self._same_origin(page_url, target) else "low"
        issue = ux_finding_defaults(
            "broken_links",
            "Broken Links",
            page_url,
            "rendered",
            title="Broken link detected",
            severity=severity,
            confidence="measured",
            selector=link.get("selector"),
            evidence={
                "rule_id": "broken-link",
                "description": f"Link target {target} failed: {reason}.",
                "metric": "status_code",
                "value": status_code or reason,
                "threshold": "<400",
            },
            user_impact="Visitors may hit dead ends, lose trust, or fail to reach key launch content.",
            technical_remediation="Update the link target, restore the destination route, or remove the link before launch.",
            references=[],
        )
        issue["builder_prompt"] = build_builder_prompt(issue)
        return issue

    def scan(self, url: str, page_paths: list[str] | None = None) -> dict[str, Any]:
        pages = build_page_targets(url, page_paths)
        issues: list[dict[str, Any]] = []
        checked_links: list[dict[str, Any]] = []

        for page_url in pages:
            try:
                links = self._extract_links(page_url)
            except PlaywrightTimeoutError:
                issue = ux_finding_defaults(
                    "broken_links",
                    "Broken Links",
                    page_url,
                    "rendered",
                    title="Page links could not be evaluated",
                    severity="medium",
                    confidence="measured",
                    evidence={"rule_id": "page-timeout", "description": "The page did not finish loading before link extraction timed out."},
                    user_impact="Broken links may remain undetected on this page.",
                    technical_remediation="Reduce page load blockers so link checks can complete.",
                )
                issue["builder_prompt"] = build_builder_prompt(issue)
                issues.append(issue)
                continue

            for link in links:
                ok, status_code, reason = self._check_link(link["url"])
                checked_links.append({
                    "source_url": page_url,
                    "target_url": link["url"],
                    "status_code": status_code,
                    "ok": ok,
                    "reason": reason,
                })
                if not ok:
                    issues.append(self._issue(page_url, link, status_code, reason))

        normalized = normalize_ux_findings(issues, default_scanner="broken_links", default_category="Broken Links")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "checked_links": checked_links,
            "recommendations": [
                "Fix or remove same-origin links that return 4xx/5xx responses before launch.",
                "Review external broken links because they reduce user trust and can interrupt conversion flows.",
            ] if normalized else [],
            "score": max(0, 100 - (len(normalized) * 8)),
        }
