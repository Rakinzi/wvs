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


class SEOScanner:
    def __init__(self, timeout_seconds: int | None = None):
        self.timeout_ms = (timeout_seconds or settings.ux_scan_page_timeout_seconds) * 1000
        self.http_timeout = timeout_seconds or settings.ux_scan_page_timeout_seconds

    def _issue(
        self,
        page_url: str,
        *,
        title: str,
        severity: str,
        rule_id: str,
        description: str,
        selector: str | None = None,
        user_impact: str,
        technical_remediation: str,
        value: Any = None,
        threshold: Any = None,
    ) -> dict[str, Any]:
        issue = ux_finding_defaults(
            "seo",
            "SEO Readiness",
            page_url,
            "rendered",
            title=title,
            severity=severity,
            confidence="measured",
            selector=selector,
            evidence={
                "rule_id": rule_id,
                "description": description,
                "metric": rule_id,
                "value": value,
                "threshold": threshold,
            },
            user_impact=user_impact,
            technical_remediation=technical_remediation,
            references=[],
        )
        issue["builder_prompt"] = build_builder_prompt(issue)
        return issue

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _check_site_files(self, url: str) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        origin = self._origin(url)
        checks = [
            (
                "robots.txt",
                "robots.txt is missing or unreachable",
                "robots-txt",
                "Add a robots.txt file that declares crawl policy and links to your sitemap.",
            ),
            (
                "sitemap.xml",
                "sitemap.xml is missing or unreachable",
                "sitemap-xml",
                "Add a sitemap.xml file and submit it in Google Search Console.",
            ),
        ]

        for path, title, rule_id, remediation in checks:
            target = urljoin(origin + "/", path)
            try:
                response = requests.get(target, timeout=self.http_timeout, allow_redirects=True)
                body = response.text.strip()
                lowered = body[:200].lower()
                if path == "robots.txt":
                    valid_body = bool(body) and "<!doctype" not in lowered and "<html" not in lowered
                else:
                    valid_body = (
                        bool(body)
                        and "<!doctype" not in lowered
                        and "<html" not in lowered
                        and ("<urlset" in body.lower() or "<sitemapindex" in body.lower())
                    )
                ok = response.status_code == 200 and valid_body
            except requests.RequestException:
                ok = False
            if ok:
                continue
            issues.append(
                self._issue(
                    url,
                    title=title,
                    severity="low",
                    rule_id=rule_id,
                    description=f"{target} did not return a non-empty 200 response.",
                    user_impact="Search engines may have a harder time discovering and crawling launch pages predictably.",
                    technical_remediation=remediation,
                )
            )
        return issues

    def _rendered_page_payload(self, page) -> dict[str, Any]:
        return page.evaluate(
            """
            () => {
              const attr = (selector, attrName) => document.querySelector(selector)?.getAttribute(attrName) || '';
              const text = (selector) => document.querySelector(selector)?.textContent?.trim() || '';
              const metas = Array.from(document.querySelectorAll('meta')).map((el) => ({
                name: el.getAttribute('name') || '',
                property: el.getAttribute('property') || '',
                content: el.getAttribute('content') || '',
              }));
              const h1s = Array.from(document.querySelectorAll('h1')).map((el) => el.textContent.trim()).filter(Boolean);
              const images = Array.from(document.querySelectorAll('img')).map((el, index) => ({
                selector: el.id ? `#${el.id}` : `img:nth-of-type(${index + 1})`,
                alt: el.getAttribute('alt'),
                visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
              }));
              const links = Array.from(document.querySelectorAll('a[href]')).map((el) => el.href);
              const jsonLd = Array.from(document.querySelectorAll('script[type="application/ld+json"]')).map((el) => el.textContent || '');
              return {
                title: document.title || '',
                description: attr('meta[name="description"]', 'content'),
                canonical: attr('link[rel="canonical"]', 'href'),
                robots: attr('meta[name="robots"]', 'content'),
                viewport: attr('meta[name="viewport"]', 'content'),
                lang: document.documentElement.getAttribute('lang') || '',
                h1s,
                h1Text: text('h1'),
                images,
                links,
                jsonLd,
                openGraph: {
                  title: metas.find((m) => m.property === 'og:title')?.content || '',
                  description: metas.find((m) => m.property === 'og:description')?.content || '',
                  image: metas.find((m) => m.property === 'og:image')?.content || '',
                },
                twitter: {
                  card: metas.find((m) => m.name === 'twitter:card')?.content || '',
                  title: metas.find((m) => m.name === 'twitter:title')?.content || '',
                  description: metas.find((m) => m.name === 'twitter:description')?.content || '',
                  image: metas.find((m) => m.name === 'twitter:image')?.content || '',
                },
              };
            }
            """
        )

    def _classify_page_type(self, page_url: str, configured_page_type: str | None) -> str:
        if configured_page_type:
            return configured_page_type.strip().lower()
        path = (urlparse(page_url).path or "").lower()
        if any(part in path for part in ("/login", "/register", "/reset-password", "/forgot-password")):
            return "auth"
        if any(part in path for part in ("/dashboard", "/settings", "/account", "/admin")):
            return "private_app"
        if any(part in path for part in ("/blog", "/article", "/news")):
            return "article"
        if any(part in path for part in ("/pricing", "/features", "/product", "/service")):
            return "product"
        return "public_landing"

    def _is_indexing_optional_page(self, page_type: str) -> bool:
        return page_type in {"auth", "login", "register", "private_app", "dashboard", "checkout", "account"}

    def _issues_from_payload(self, page_url: str, payload: dict[str, Any], page_type: str | None = None) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        resolved_page_type = self._classify_page_type(page_url, page_type)
        indexing_optional = self._is_indexing_optional_page(resolved_page_type)
        title = str(payload.get("title") or "").strip()
        description = str(payload.get("description") or "").strip()
        canonical = str(payload.get("canonical") or "").strip()
        robots = str(payload.get("robots") or "").lower()
        h1s = payload.get("h1s") or []
        images = payload.get("images") or []
        json_ld = payload.get("jsonLd") or []
        open_graph = payload.get("openGraph") or {}
        twitter = payload.get("twitter") or {}

        if not title:
            issues.append(self._issue(
                page_url,
                title="Page title is missing",
                severity="high",
                rule_id="title-missing",
                description="The rendered document has an empty <title>.",
                selector="title",
                user_impact="Search results and browser tabs will not clearly describe the page.",
                technical_remediation="Add a unique, descriptive title tag for this page.",
            ))
        elif len(title) < 15 or len(title) > 65:
            issues.append(self._issue(
                page_url,
                title="Page title length is outside the recommended range",
                severity="low",
                rule_id="title-length",
                description=f"Title length is {len(title)} characters.",
                selector="title",
                user_impact="Search result snippets may be unclear or truncated.",
                technical_remediation="Use a concise, unique title of roughly 15-65 characters.",
                value=len(title),
                threshold="15-65",
            ))

        if not description and not indexing_optional:
            issues.append(self._issue(
                page_url,
                title="Meta description is missing",
                severity="medium",
                rule_id="meta-description-missing",
                description='No meta[name="description"] tag was found.',
                selector='meta[name="description"]',
                user_impact="Search previews may use arbitrary page text instead of a crafted product message.",
                technical_remediation="Add a compelling meta description for this page.",
            ))
        elif description and not indexing_optional and (len(description) < 50 or len(description) > 170):
            issues.append(self._issue(
                page_url,
                title="Meta description length is outside the recommended range",
                severity="low",
                rule_id="meta-description-length",
                description=f"Meta description length is {len(description)} characters.",
                selector='meta[name="description"]',
                user_impact="Search previews may be too vague or get truncated.",
                technical_remediation="Use a descriptive meta description of roughly 50-170 characters.",
                value=len(description),
                threshold="50-170",
            ))

        if not canonical and not indexing_optional:
            issues.append(self._issue(
                page_url,
                title="Canonical URL is missing",
                severity="low",
                rule_id="canonical-missing",
                description='No link[rel="canonical"] tag was found.',
                selector='link[rel="canonical"]',
                user_impact="Duplicate URLs may split ranking signals or confuse crawlers.",
                technical_remediation="Add a canonical link that points to the preferred public URL for this page.",
            ))

        if "noindex" in robots and not indexing_optional:
            issues.append(self._issue(
                page_url,
                title="Page is marked noindex",
                severity="high",
                rule_id="meta-robots-noindex",
                description=f"Meta robots content is '{robots}'.",
                selector='meta[name="robots"]',
                user_impact="Search engines are instructed not to index this launch page.",
                technical_remediation="Remove noindex before launch unless this page should remain private.",
            ))

        if len(h1s) == 0 and not indexing_optional:
            issues.append(self._issue(
                page_url,
                title="Page is missing an H1",
                severity="medium",
                rule_id="h1-missing",
                description="No rendered <h1> was found.",
                selector="h1",
                user_impact="Users and crawlers may struggle to identify the primary topic of the page.",
                technical_remediation="Add one clear H1 that describes the page's main offer or purpose.",
            ))
        elif len(h1s) > 1:
            issues.append(self._issue(
                page_url,
                title="Page has multiple H1 headings",
                severity="low",
                rule_id="h1-multiple",
                description=f"{len(h1s)} rendered H1 headings were found.",
                selector="h1",
                user_impact="The page hierarchy may be ambiguous for users and crawlers.",
                technical_remediation="Use one primary H1 and demote secondary headings to H2/H3 where appropriate.",
                value=len(h1s),
                threshold=1,
            ))

        missing_alt = [img for img in images if img.get("visible") and not (img.get("alt") or "").strip()]
        if missing_alt:
            first = missing_alt[0]
            issues.append(self._issue(
                page_url,
                title="Visible images are missing alt text",
                severity="medium",
                rule_id="image-alt-missing",
                description=f"{len(missing_alt)} visible image(s) have empty or missing alt text.",
                selector=first.get("selector"),
                user_impact="Image search, accessibility, and content understanding may suffer.",
                technical_remediation="Add meaningful alt text to informative images and empty alt text only for decorative images.",
                value=len(missing_alt),
                threshold=0,
            ))

        if not json_ld and not indexing_optional:
            issues.append(self._issue(
                page_url,
                title="Structured data is missing",
                severity="recommendation",
                rule_id="json-ld-missing",
                description='No script[type="application/ld+json"] block was found.',
                selector='script[type="application/ld+json"]',
                user_impact="Search engines may have less context for rich results and brand/entity understanding.",
                technical_remediation="Add relevant JSON-LD such as Organization, WebSite, Product, SoftwareApplication, or BreadcrumbList where appropriate.",
            ))
        else:
            invalid_count = 0
            import json

            for block in json_ld:
                try:
                    json.loads(block)
                except Exception:
                    invalid_count += 1
            if invalid_count:
                issues.append(self._issue(
                    page_url,
                    title="Structured data contains invalid JSON",
                    severity="medium",
                    rule_id="json-ld-invalid",
                    description=f"{invalid_count} JSON-LD block(s) could not be parsed.",
                    selector='script[type="application/ld+json"]',
                    user_impact="Invalid structured data will be ignored by search engines.",
                    technical_remediation="Fix JSON-LD syntax and validate with Google's Rich Results Test.",
                    value=invalid_count,
                    threshold=0,
                ))

        og_missing = [key for key in ("title", "description", "image") if not open_graph.get(key)]
        if og_missing and not indexing_optional:
            issues.append(self._issue(
                page_url,
                title="Open Graph metadata is incomplete",
                severity="low",
                rule_id="open-graph-incomplete",
                description=f"Missing Open Graph fields: {', '.join(og_missing)}.",
                selector='meta[property^="og:"]',
                user_impact="Shared links may look weak or unclear on social platforms and messaging apps.",
                technical_remediation="Add og:title, og:description, and og:image for key launch pages.",
            ))

        twitter_missing = [key for key in ("card", "title", "description", "image") if not twitter.get(key)]
        if twitter_missing and not indexing_optional:
            issues.append(self._issue(
                page_url,
                title="Twitter/X card metadata is incomplete",
                severity="recommendation",
                rule_id="twitter-card-incomplete",
                description=f"Missing Twitter card fields: {', '.join(twitter_missing)}.",
                selector='meta[name^="twitter:"]',
                user_impact="Shared links may not produce a strong card preview on X and compatible platforms.",
                technical_remediation="Add twitter:card, twitter:title, twitter:description, and twitter:image for key launch pages.",
            ))

        if indexing_optional and "noindex" not in robots:
            issues.append(self._issue(
                page_url,
                title="Application/auth page is not explicitly excluded from indexing",
                severity="recommendation",
                rule_id="app-page-indexing-policy",
                description=f"Page type '{resolved_page_type}' often should not be indexed; no noindex directive was detected.",
                selector='meta[name="robots"]',
                user_impact="Private or utility pages may appear in search results if they are publicly reachable.",
                technical_remediation="If this page is not intended for search traffic, add a noindex directive or enforce authentication.",
            ))

        return issues

    def scan(self, url: str, page_paths: list[str] | None = None, page_type: str | None = None) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        pages = build_page_targets(url, page_paths)[: min(settings.ux_scan_max_pages, 5)]
        if pages:
            issues.extend(self._check_site_files(pages[0]))

        page_payloads: dict[str, Any] = {}
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(viewport={"width": settings.ux_scan_desktop_width, "height": settings.ux_scan_desktop_height})
                page = context.new_page()
                for page_url in pages:
                    try:
                        response = page.goto(page_url, wait_until="networkidle", timeout=self.timeout_ms)
                        status = response.status if response else None
                        if status and status >= 400:
                            issues.append(self._issue(
                                page_url,
                                title="Page returns an unsuccessful HTTP status",
                                severity="high",
                                rule_id="http-status",
                                description=f"Rendered page returned HTTP status {status}.",
                                user_impact="Search engines may not index pages that fail to load successfully.",
                                technical_remediation="Fix server routing or deployment errors so the page returns a 2xx status.",
                                value=status,
                                threshold="2xx",
                            ))
                        payload = self._rendered_page_payload(page)
                        page_payloads[page_url] = payload
                        issues.extend(self._issues_from_payload(page_url, payload, page_type=page_type))
                    except PlaywrightTimeoutError:
                        issues.append(self._issue(
                            page_url,
                            title="Page could not be evaluated for SEO",
                            severity="medium",
                            rule_id="page-timeout",
                            description="The page did not finish loading before the SEO scan timed out.",
                            user_impact="SEO defects may remain undetected if the rendered page cannot be inspected.",
                            technical_remediation="Reduce load blockers or fix runtime errors so the page can render reliably.",
                        ))
            finally:
                browser.close()

        normalized = normalize_ux_findings(issues, default_scanner="seo", default_category="SEO Readiness")
        return {
            "status": "issues_found" if normalized else "ok",
            "issues": normalized,
            "raw": page_payloads,
            "recommendations": [
                "Create unique titles, descriptions, canonicals, and H1s for each launch page.",
                "Add robots.txt, sitemap.xml, and relevant JSON-LD before indexing public pages.",
                "Validate social previews before launch so shared links look trustworthy.",
            ] if normalized else [],
            "score": max(0, 100 - (len(normalized) * 7)),
        }
