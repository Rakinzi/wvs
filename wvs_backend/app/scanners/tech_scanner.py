from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright


# ── Signature database ───────────────────────────────────────────────────────
# Each entry: pattern matched against HTML/headers/scripts, mapped to a category and tech name.
SIGNATURES: list[dict] = [
    # CMS
    {"pattern": re.compile(r'/wp-content/|/wp-includes/|wp-json', re.I), "category": "cms", "name": "WordPress"},
    {"pattern": re.compile(r'Joomla!|/components/com_', re.I), "category": "cms", "name": "Joomla"},
    {"pattern": re.compile(r'Drupal\.settings|/sites/default/files/', re.I), "category": "cms", "name": "Drupal"},
    {"pattern": re.compile(r'shopify\.com|Shopify\.theme', re.I), "category": "cms", "name": "Shopify"},
    {"pattern": re.compile(r'squarespace\.com|static\.squarespace', re.I), "category": "cms", "name": "Squarespace"},
    {"pattern": re.compile(r'ghost\.org|content/themes/casper', re.I), "category": "cms", "name": "Ghost"},
    {"pattern": re.compile(r'wix\.com|X-Wix-', re.I), "category": "cms", "name": "Wix"},

    # JS frameworks
    {"pattern": re.compile(r'react(?:\.min)?\.js|__REACT_DEVTOOLS|_jsx\(', re.I), "category": "javascript-frameworks", "name": "React"},
    {"pattern": re.compile(r'vue(?:\.min)?\.js|Vue\.config|createApp\(', re.I), "category": "javascript-frameworks", "name": "Vue.js"},
    {"pattern": re.compile(r'angular(?:\.min)?\.js|ng-version|ng-app', re.I), "category": "javascript-frameworks", "name": "AngularJS"},
    {"pattern": re.compile(r'@angular/core|platformBrowserDynamic', re.I), "category": "javascript-frameworks", "name": "Angular"},
    {"pattern": re.compile(r'next\.js|__NEXT_DATA__|_next/static', re.I), "category": "javascript-frameworks", "name": "Next.js"},
    {"pattern": re.compile(r'nuxt\.js|__NUXT__|_nuxt/', re.I), "category": "javascript-frameworks", "name": "Nuxt.js"},
    {"pattern": re.compile(r'svelte|__svelte', re.I), "category": "javascript-frameworks", "name": "Svelte"},
    {"pattern": re.compile(r'jquery[.-](\d[\d.]+)(?:\.min)?\.js|jQuery v(\d[\d.]+)', re.I), "category": "javascript-libraries", "name": "jQuery"},
    {"pattern": re.compile(r'jquery-migrate[.-](\d[\d.]+)', re.I), "category": "javascript-libraries", "name": "jQuery Migrate"},
    {"pattern": re.compile(r'jquery-ui[.-](\d[\d.]+)', re.I), "category": "javascript-libraries", "name": "jQuery UI"},
    {"pattern": re.compile(r'moment(?:\.min)?\.js|moment\.version', re.I), "category": "javascript-libraries", "name": "Moment.js"},
    {"pattern": re.compile(r'core-js|core\.js', re.I), "category": "javascript-libraries", "name": "core-js"},
    {"pattern": re.compile(r'lodash(?:\.min)?\.js|_\.VERSION', re.I), "category": "javascript-libraries", "name": "Lodash"},
    {"pattern": re.compile(r'bootstrap(?:\.min)?\.js|bootstrap(?:\.min)?\.css', re.I), "category": "css-frameworks", "name": "Bootstrap"},
    {"pattern": re.compile(r'tailwindcss|tailwind\.config', re.I), "category": "css-frameworks", "name": "Tailwind CSS"},
    {"pattern": re.compile(r'materialize(?:\.min)?\.css', re.I), "category": "css-frameworks", "name": "Materialize"},

    # Web servers (from headers)
    {"pattern": re.compile(r'nginx', re.I), "category": "web-servers", "name": "Nginx", "header": "server"},
    {"pattern": re.compile(r'openresty', re.I), "category": "web-servers", "name": "OpenResty", "header": "server"},
    {"pattern": re.compile(r'apache', re.I), "category": "web-servers", "name": "Apache", "header": "server"},
    {"pattern": re.compile(r'microsoft-iis', re.I), "category": "web-servers", "name": "IIS", "header": "server"},
    {"pattern": re.compile(r'lighttpd', re.I), "category": "web-servers", "name": "Lighttpd", "header": "server"},
    {"pattern": re.compile(r'cloudflare', re.I), "category": "cdn", "name": "Cloudflare", "header": "server"},

    # Languages (from headers)
    {"pattern": re.compile(r'php', re.I), "category": "programming-languages", "name": "PHP", "header": "x-powered-by"},
    {"pattern": re.compile(r'asp\.net', re.I), "category": "programming-languages", "name": "ASP.NET", "header": "x-powered-by"},
    {"pattern": re.compile(r'lua', re.I), "category": "programming-languages", "name": "Lua", "header": "x-powered-by"},

    # Analytics / tag managers
    {"pattern": re.compile(r'google-analytics\.com/analytics\.js|gtag\(|UA-\d{4,10}-\d', re.I), "category": "analytics", "name": "Google Analytics"},
    {"pattern": re.compile(r'googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+', re.I), "category": "tag-managers", "name": "Google Tag Manager"},
    {"pattern": re.compile(r'facebook\.net/en_US/fbevents\.js|fbq\(', re.I), "category": "analytics", "name": "Facebook Pixel"},
    {"pattern": re.compile(r'hotjar\.com', re.I), "category": "analytics", "name": "Hotjar"},

    # CDN / meta
    {"pattern": re.compile(r'cloudflare-static|cf-ray', re.I), "category": "cdn", "name": "Cloudflare"},
    {"pattern": re.compile(r'cdn\.jsdelivr\.net', re.I), "category": "cdn", "name": "jsDelivr"},
    {"pattern": re.compile(r'unpkg\.com', re.I), "category": "cdn", "name": "unpkg"},
    {"pattern": re.compile(r'cdnjs\.cloudflare\.com', re.I), "category": "cdn", "name": "cdnjs"},

    # Structured data / Open Graph / SEO
    {"pattern": re.compile(r'application/ld\+json', re.I), "category": "miscellaneous", "name": "JSON-LD"},
    {"pattern": re.compile(r'og:title|og:description|og:image', re.I), "category": "miscellaneous", "name": "Open Graph"},
    {"pattern": re.compile(r'<link[^>]+type=["\']application/rss\+xml', re.I), "category": "miscellaneous", "name": "RSS"},

    # Databases (inferred from CMS)
    {"pattern": re.compile(r'/wp-content/|/wp-includes/'), "category": "databases", "name": "MySQL"},

    # eCommerce
    {"pattern": re.compile(r'WooCommerce|woocommerce', re.I), "category": "ecommerce", "name": "WooCommerce"},
    {"pattern": re.compile(r'Magento|/mage/adminhtml|Mage\.Cookies', re.I), "category": "ecommerce", "name": "Magento"},

    # WordPress signals PHP (WordPress requires PHP)
    {"pattern": re.compile(r'/wp-content/|/wp-includes/'), "category": "programming-languages", "name": "PHP"},

    # WordPress API link header signals wp-json
    {"pattern": re.compile(r'rel=["\']https://api\.w\.org/', re.I), "category": "cms", "name": "WordPress"},

    # Plugins
    {"pattern": re.compile(r'/wp-content/plugins/([^/\"\']+)', re.I), "category": "wordpress-plugins", "name": "__PLUGIN__"},
]

PLUGIN_RE = re.compile(r'/wp-content/plugins/([^/\"\'<>\s]+)', re.I)

RISKY_TECHS = {
    "wordpress": "Ensure WordPress core, themes, and plugins are up to date.",
    "woocommerce": "WooCommerce handles payments — ensure PCI compliance and keep plugins updated.",
    "joomla": "Ensure Joomla and all extensions are up to date.",
    "drupal": "Ensure Drupal core and modules are up to date.",
    "php": "Ensure PHP version is current and not end-of-life.",
    "jquery": "Outdated jQuery versions have known XSS vulnerabilities.",
    "bootstrap": "Older Bootstrap versions may have XSS vulnerabilities.",
    "apache": "Ensure Apache is patched and server banner is hidden.",
    "nginx": "Ensure Nginx is patched and server banner is hidden.",
    "iis": "Ensure IIS is patched and detailed error messages are disabled.",
}

SERVER_BANNER_RE = re.compile(r"(apache|nginx|iis|openresty|lighttpd)[/\s]?([\d.]+)?", re.IGNORECASE)
WP_VERSION_RE = re.compile(r'content="WordPress (\d[\d.]+)"')
JQUERY_VERSION_RE = re.compile(r'jquery[.-]([\d.]+)(?:\.min)?\.js', re.I)
BOOTSTRAP_VERSION_RE = re.compile(r'bootstrap(?:[.-]bundle)?[.-]([\d.]+)(?:\.min)?\.(?:js|css)', re.I)

OUTDATED_VERSION_FLOORS = {
    "jQuery": (3, 5, 0),
    "Bootstrap": (5, 2, 0),
}

PACKAGE_SOURCE_PATTERNS = [
    (re.compile(r'cdnjs\.cloudflare\.com/ajax/libs/(?P<name>[^/]+)/(?P<version>[^/]+)/', re.I), None),
    (re.compile(r'cdn\.jsdelivr\.net/npm/(?P<name>@?[^@/]+(?:/[^@/]+)?)@(?P<version>[^/]+)', re.I), None),
    (re.compile(r'unpkg\.com/(?P<name>@?[^@/]+(?:/[^@/]+)?)@(?P<version>[^/]+)', re.I), None),
    (re.compile(r'jquery[.-](?P<version>\d[\d.]+)(?:\.min)?\.js', re.I), "jquery"),
    (re.compile(r'bootstrap(?:[.-]bundle)?[.-](?P<version>\d[\d.]+)(?:\.min)?\.(?:js|css)', re.I), "bootstrap"),
    (re.compile(r'lodash(?:\.min)?[.-](?P<version>\d[\d.]+)\.js', re.I), "lodash"),
    (re.compile(r'moment(?:\.min)?[.-](?P<version>\d[\d.]+)\.js', re.I), "moment"),
    (re.compile(r'core-js[/-](?P<version>\d[\d.]+)/', re.I), "core-js"),
]

PACKAGE_NAME_MAP = {
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "lodash": "lodash",
    "moment": "moment",
    "core-js": "core-js",
}


def _fetch_with_playwright(url: str, timeout: int) -> tuple[str, dict]:
    """Returns (html, response_headers) after executing JS and following all redirects."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent="Mozilla/5.0 (compatible; WVS-TechScanner/2.0)")
        page = context.new_page()

        # Capture headers from the final settled response, not intermediate redirects
        all_responses: list = []
        page.on("response", lambda r: all_responses.append(r))

        page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
        html = page.content()
        final_url = page.url

        # Pick the last response that matches the final URL
        captured_headers: dict = {}
        for r in reversed(all_responses):
            if r.url == final_url:
                try:
                    captured_headers = dict(r.headers)
                except Exception:
                    pass
                break

        browser.close()
    return html, {k.lower(): v for k, v in captured_headers.items()}


def _fetch_with_httpx(url: str, timeout: int) -> tuple[str, dict]:
    client = httpx.Client(
        timeout=timeout, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; WVS-TechScanner/2.0)"},
    )
    resp = client.get(url)
    client.close()
    return resp.text, {k.lower(): v for k, v in resp.headers.items()}


def _fingerprint(html: str, headers: dict) -> dict[str, list[str]]:
    techs: dict[str, set] = {}
    # Combine html + link header for header-based sigs
    link_header = headers.get("link", "")
    html_plus_link = html + "\n" + link_header

    for sig in SIGNATURES:
        if sig["name"] == "__PLUGIN__":
            continue
        target_header = sig.get("header")
        if target_header:
            source = headers.get(target_header, "")
        else:
            source = html_plus_link
        if sig["pattern"].search(source):
            techs.setdefault(sig["category"], set()).add(sig["name"])

    # Deduplicate web-servers — OpenResty implies Nginx
    if "web-servers" in techs and "OpenResty" in techs["web-servers"]:
        techs["web-servers"].discard("Nginx")

    # Extract WordPress plugins
    plugins = {m.group(1) for m in PLUGIN_RE.finditer(html)}
    if plugins:
        techs["wordpress-plugins"] = plugins

    return {cat: sorted(names) for cat, names in techs.items()}


def _extract_versions(html: str) -> dict[str, str]:
    versions = {}
    m = WP_VERSION_RE.search(html)
    if m:
        versions["WordPress"] = m.group(1)
    m = JQUERY_VERSION_RE.search(html)
    if m:
        versions["jQuery"] = m.group(1)
    m = BOOTSTRAP_VERSION_RE.search(html)
    if m:
        versions["Bootstrap"] = m.group(1)
    return versions


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in re.split(r"[^\d]+", version):
        if chunk:
            parts.append(int(chunk))
    return tuple(parts)


def _version_lt(version: str, floor: tuple[int, ...]) -> bool:
    current = _version_tuple(version)
    if not current:
        return False
    normalized_current = current + (0,) * (len(floor) - len(current))
    return normalized_current[:len(floor)] < floor


def _looks_like_directory_listing(html: str) -> bool:
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    heading = " ".join(h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"], limit=3))

    signals = [
        title.lower().startswith("index of /"),
        "directory listing for" in title.lower(),
        heading.lower().startswith("index of /"),
        bool(soup.find("a", href=re.compile(r"^\.\./?$"))),
        bool(soup.find(string=re.compile(r"\bParent Directory\b", re.I))),
    ]
    return sum(1 for s in signals if s) >= 2


def _extract_packages(html: str, base_url: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    discovered: dict[tuple[str, str], dict[str, str]] = {}

    candidates = []
    for tag in soup.find_all(["script", "link"]):
        raw = tag.get("src") or tag.get("href")
        if raw:
            candidates.append(urljoin(base_url, raw))

    for source in candidates:
        parsed = urlparse(source)
        candidate = source
        if parsed.query:
            candidate = candidate.replace(f"?{parsed.query}", "")

        for pattern, forced_name in PACKAGE_SOURCE_PATTERNS:
            match = pattern.search(candidate)
            if not match:
                continue
            name = forced_name or match.groupdict().get("name")
            version = match.groupdict().get("version")
            if not name or not version:
                continue
            normalized_name = PACKAGE_NAME_MAP.get(name.lower(), name.lower())
            key = (normalized_name, version)
            discovered[key] = {
                "name": normalized_name,
                "version": version,
                "ecosystem": "npm",
                "source": source,
            }
            break

    return sorted(discovered.values(), key=lambda item: (item["name"], item["version"]))


def _extract_fixed_versions(vuln: dict[str, Any]) -> list[str]:
    fixed_versions: set[str] = set()
    for affected in vuln.get("affected", []) or []:
        for entry in affected.get("ranges", []) or []:
            for event in entry.get("events", []) or []:
                fixed = event.get("fixed")
                if fixed:
                    fixed_versions.add(fixed)
    return sorted(fixed_versions)


def _extract_cwes(vuln: dict[str, Any]) -> list[str]:
    database_specific = vuln.get("database_specific", {}) or {}
    cwe_ids = database_specific.get("cwe_ids") or database_specific.get("cwes") or []
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]
    return sorted({str(cwe).strip() for cwe in cwe_ids if str(cwe).strip()})


def _advisory_severity(vuln: dict[str, Any]) -> str:
    database_specific = vuln.get("database_specific", {}) or {}
    severity = str(database_specific.get("severity") or "").strip().title()
    if severity in {"Critical", "High", "Medium", "Low"}:
        return severity

    aliases = vuln.get("aliases", []) or []
    if any(str(alias).startswith("CVE-") for alias in aliases):
        return "High"
    return "Medium"


class TechScanner:
    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        self.advisory_client = httpx.Client(
            timeout=min(timeout, 10),
            headers={"User-Agent": "WVS-TechScanner/2.0"},
        )

    def _query_osv(self, packages: list[dict[str, str]]) -> list[dict[str, Any]]:
        advisories: list[dict[str, Any]] = []
        for package in packages[:15]:
            try:
                response = self.advisory_client.post(
                    "https://api.osv.dev/v1/query",
                    json={
                        "package": {
                            "name": package["name"],
                            "ecosystem": package["ecosystem"],
                        },
                        "version": package["version"],
                    },
                )
                response.raise_for_status()
                payload = response.json()
            except Exception:
                continue

            for vuln in payload.get("vulns", []) or []:
                aliases = vuln.get("aliases", []) or []
                cves = [alias for alias in aliases if str(alias).startswith("CVE-")]
                advisory = {
                    "package": package["name"],
                    "version": package["version"],
                    "ecosystem": package["ecosystem"],
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary") or (vuln.get("details") or "").splitlines()[0][:180],
                    "aliases": aliases,
                    "cves": cves,
                    "cwes": _extract_cwes(vuln),
                    "severity": _advisory_severity(vuln),
                    "fixed_versions": _extract_fixed_versions(vuln),
                    "references": [
                        ref.get("url")
                        for ref in (vuln.get("references", []) or [])
                        if ref.get("url")
                    ][:5],
                }
                advisories.append(advisory)
        return advisories

    def _check_server_banner(self, headers: dict) -> list[dict]:
        issues = []
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        if server and SERVER_BANNER_RE.search(server):
            issues.append({
                "name": "Server version exposed in headers",
                "severity": "Low",
                "evidence": server,
            })
        if x_powered:
            issues.append({
                "name": "Technology stack exposed via X-Powered-By",
                "severity": "Low",
                "evidence": x_powered,
            })
        return issues

    def scan(self, url: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "ok",
            "url": url,
            "technologies": {},
            "versions": {},
            "packages": [],
            "advisories": [],
            "issues": [],
            "recommendations": [],
            "score": 100,
        }

        # Try Playwright first (handles JS challenges, SPAs, anti-bot gates)
        try:
            html, headers = _fetch_with_playwright(url, self.timeout)
        except Exception:
            try:
                html, headers = _fetch_with_httpx(url, self.timeout)
            except Exception as exc:
                return {
                    "status": "error", "url": url, "score": 0,
                    "issues": [{"name": "Tech scan failed", "evidence": str(exc), "severity": "Low"}],
                }

        result["technologies"] = _fingerprint(html, headers)
        result["versions"] = _extract_versions(html)
        result["packages"] = _extract_packages(html, url)
        result["advisories"] = self._query_osv(result["packages"])

        if _looks_like_directory_listing(html):
            result["issues"].append({
                "name": "Directory listing appears enabled",
                "severity": "Medium",
                "evidence": "The response resembles a web server directory index page.",
            })
            result["recommendations"].append("Disable autoindex / directory browsing on the web server and serve explicit index files only.")

        # Header leakage
        banner_issues = self._check_server_banner(headers)
        result["issues"].extend(banner_issues)
        if any("Server version" in i["name"] for i in banner_issues):
            result["recommendations"].append("Hide server version (ServerTokens Prod / server_tokens off).")
        if any("X-Powered-By" in i["name"] for i in banner_issues):
            result["recommendations"].append("Remove the X-Powered-By header to reduce information exposure.")

        for tech_name, version in result["versions"].items():
            floor = OUTDATED_VERSION_FLOORS.get(tech_name)
            if floor and _version_lt(version, floor):
                result["issues"].append({
                    "name": f"Outdated {tech_name} version detected",
                    "severity": "Medium",
                    "evidence": f"Detected version {version}; recommended baseline is {'.'.join(map(str, floor))} or newer.",
                })
                result["recommendations"].append(f"Upgrade {tech_name} to {'.'.join(map(str, floor))} or newer and review related client-side advisories.")

        if result["packages"]:
            result["recommendations"].extend([
                "Maintain a software bill of materials (SBOM) for exposed client-side packages.",
                "Pin dependency versions and keep lockfiles in source control.",
                "Run automated dependency scanning in CI/CD (for example OSV-Scanner, Dependabot, or Renovate).",
                "Use Subresource Integrity (SRI) or self-host critical third-party scripts loaded from CDNs.",
            ])

        for advisory in result["advisories"]:
            cve_text = ", ".join(advisory["cves"][:3]) if advisory["cves"] else advisory["id"]
            cwe_text = ", ".join(advisory["cwes"][:3]) if advisory["cwes"] else "CWE not published"
            fixed_text = (
                f" Fixed in: {', '.join(advisory['fixed_versions'][:3])}."
                if advisory["fixed_versions"] else ""
            )
            result["issues"].append({
                "name": f"Known vulnerability in {advisory['package']}@{advisory['version']}",
                "severity": advisory["severity"],
                "evidence": f"{cve_text} | {cwe_text}.{fixed_text}",
            })
            result["recommendations"].append(
                f"Upgrade {advisory['package']} from {advisory['version']} to a patched release and review the related advisory references."
            )

        # Flag risky techs
        all_techs_lower = {
            t.lower()
            for names in result["technologies"].values()
            for t in names
        }
        for risky, rec in RISKY_TECHS.items():
            if any(risky in t for t in all_techs_lower):
                result["issues"].append({
                    "name": f"Detected: {next(t for t in all_techs_lower if risky in t).title()}",
                    "severity": "Info",
                    "evidence": f"Identified in the tech stack.",
                })
                result["recommendations"].append(rec)

        non_info = [i for i in result["issues"] if i["severity"] != "Info"]
        seen_recommendations: set[str] = set()
        result["recommendations"] = [
            rec for rec in result["recommendations"]
            if not (rec in seen_recommendations or seen_recommendations.add(rec))
        ]
        result["score"] = max(0, 100 - len(non_info) * 15)
        result["status"] = "issues_found" if result["issues"] else "ok"
        return result
