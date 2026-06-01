from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import requests_cache
from bs4 import BeautifulSoup
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.scanners.external_tooling import WPScanRunner
from app.settings import settings

# InfinityFree / VistaPanel AES anti-bot challenge
# The page sets: var a=toNumbers(KEY), b=toNumbers(IV), c=toNumbers(CIPHER)
# then calls:    slowAES.decrypt(c, 2, a, b)
_CHALLENGE_VAR_RE = re.compile(
    r'var\s+a=toNumbers\("(?P<key>[0-9a-f]{32})"\)'
    r'.*?b=toNumbers\("(?P<iv>[0-9a-f]{32})"\)'
    r'.*?c=toNumbers\("(?P<cipher>[0-9a-f]{32})"\)',
    re.IGNORECASE | re.DOTALL,
)


def _solve_infinityfree_challenge(html: str) -> str | None:
    """Solve the slowAES decrypt challenge used by InfinityFree's anti-bot page.
    Returns the hex cookie value, or None if the page is not a challenge."""
    match = _CHALLENGE_VAR_RE.search(html)
    if not match:
        return None
    try:
        from Crypto.Cipher import AES
        key    = bytes.fromhex(match.group('key'))
        iv     = bytes.fromhex(match.group('iv'))
        cipher = bytes.fromhex(match.group('cipher'))
        return AES.new(key, AES.MODE_CBC, iv).decrypt(cipher).hex()
    except Exception:
        return None


PLUGIN_PATH_RE = re.compile(
    r"/wp-content/plugins/(?P<slug>[^/?#]+)/[^\"'\s?#]+(?:\?[^\"'\s#]*)?",
    re.IGNORECASE,
)
THEME_PATH_RE = re.compile(
    r"/wp-content/themes/(?P<slug>[^/?#]+)/[^\"'\s?#]+(?:\?[^\"'\s#]*)?",
    re.IGNORECASE,
)
WP_VERSION_RE = re.compile(r"WordPress\s+([0-9]+(?:\.[0-9A-Za-z-]+)+)", re.IGNORECASE)
FEED_VERSION_RE = re.compile(r"\?v=([0-9]+(?:\.[0-9A-Za-z-]+)+)")
STABLE_TAG_RE = re.compile(r"^\s*Stable Tag:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
INDEX_OF_RE = re.compile(r"<title>\s*Index of ", re.IGNORECASE)


def _split_version(value: str) -> list[Any]:
    parts = re.split(r"[.\-_+]", value)
    normalized: list[Any] = []
    for part in parts:
        if part.isdigit():
            normalized.append(int(part))
        else:
            normalized.append(part.lower())
    return normalized


def compare_versions(left: str | None, right: str | None) -> int:
    if not left or not right:
        return 0

    left_parts = _split_version(left)
    right_parts = _split_version(right)
    length = max(len(left_parts), len(right_parts))

    for index in range(length):
        left_part = left_parts[index] if index < len(left_parts) else 0
        right_part = right_parts[index] if index < len(right_parts) else 0
        if left_part == right_part:
            continue
        if isinstance(left_part, int) and isinstance(right_part, int):
            return -1 if left_part < right_part else 1
        return -1 if str(left_part) < str(right_part) else 1
    return 0


class WordPressScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.wpscan = WPScanRunner(settings.wpscan_cli_path, settings.external_tools_timeout_seconds)
        self.session = requests_cache.CachedSession(
            cache_name=f"{settings.requests_cache_name}_wordpress",
            backend="sqlite",
            expire_after=min(settings.requests_cache_ttl_seconds, 3600),
            allowable_methods=("GET",),
        )
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        })

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        reraise=True,
    )
    def _get(self, url: str, **kwargs):
        response = self.session.get(url, timeout=self.timeout, allow_redirects=True, **kwargs)
        # Transparently solve InfinityFree's AES anti-bot challenge (up to 3 rounds)
        for _ in range(3):
            cookie_value = _solve_infinityfree_challenge(response.text)
            if cookie_value is None:
                break
            self.session.cookies.set('__test', cookie_value, domain=urlparse(url).netloc)
            sep = '&' if '?' in url else '?'
            url = url.split('?i=')[0]  # strip any previous ?i= param
            url = f"{url}{sep}i=1"
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        return response

    def _get_text(self, url: str) -> tuple[int | None, str | None, str]:
        try:
            response = self._get(url)
            return response.status_code, response.headers.get("content-type"), response.text
        except Exception:
            return None, None, ""

    def _extract_version_from_html(self, html: str) -> tuple[str | None, str | None]:
        soup = BeautifulSoup(html, "html.parser")

        generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.IGNORECASE)})
        if generator and generator.get("content"):
            match = WP_VERSION_RE.search(generator["content"])
            if match:
                return match.group(1), "meta_generator"

        for generator_tag in soup.find_all("generator"):
            if generator_tag.text:
                match = FEED_VERSION_RE.search(generator_tag.text)
                if match:
                    return match.group(1), "feed_generator"

        asset_match = re.search(r"/wp-(?:includes|admin)/[^\"'\s?#]+\?ver=([0-9][^\"'&#\s]*)", html)
        if asset_match:
            return asset_match.group(1), "asset_version"

        return None, None

    def _detect_plugins(self, html: str, base_url: str) -> list[dict[str, Any]]:
        plugins: dict[str, dict[str, Any]] = {}

        for match in PLUGIN_PATH_RE.finditer(html):
            slug = match.group("slug").lower()
            asset_url = match.group(0)
            version = None
            parsed = urlparse(asset_url)
            query = parse_qs(parsed.query)
            if query.get("ver"):
                version = query["ver"][0]

            existing = plugins.get(slug)
            if existing:
                if not existing.get("version") and version:
                    existing["version"] = version
                    existing["version_source"] = "asset_query"
                continue

            plugins[slug] = {
                "slug": slug,
                "version": version,
                "version_source": "asset_query" if version else None,
                "path": asset_url,
            }

        for plugin in plugins.values():
            if plugin.get("version"):
                continue
            readme_url = urljoin(base_url, f"/wp-content/plugins/{plugin['slug']}/readme.txt")
            status_code, _, text = self._get_text(readme_url)
            if status_code == 200 and text:
                stable_tag = STABLE_TAG_RE.search(text)
                if stable_tag:
                    plugin["version"] = stable_tag.group(1).strip()
                    plugin["version_source"] = "readme_stable_tag"

        return list(plugins.values())

    def _detect_themes(self, html: str) -> list[dict[str, Any]]:
        themes: dict[str, dict[str, Any]] = {}

        for match in THEME_PATH_RE.finditer(html):
            slug = match.group("slug").lower()
            asset_url = match.group(0)
            version = None
            parsed = urlparse(asset_url)
            query = parse_qs(parsed.query)
            if query.get("ver"):
                version = query["ver"][0]

            if slug not in themes:
                themes[slug] = {
                    "slug": slug,
                    "version": version,
                    "version_source": "asset_query" if version else None,
                    "path": asset_url,
                }
            elif not themes[slug].get("version") and version:
                themes[slug]["version"] = version
                themes[slug]["version_source"] = "asset_query"

        return list(themes.values())

    def _plugin_repo_info(self, slug: str) -> dict[str, Any] | None:
        try:
            response = self._get(f"https://api.wordpress.org/plugins/info/1.0/{slug}.json")
        except Exception:
            return None

        if response.status_code != 200:
            return None

        data = response.json()
        if not isinstance(data, dict) or data.get("error"):
            return None

        return {
            "name": data.get("name"),
            "latest_version": data.get("version"),
            "last_updated": data.get("last_updated"),
            "homepage": data.get("homepage"),
        }

    def _latest_core_version(self) -> str | None:
        try:
            response = self._get("https://api.wordpress.org/core/version-check/1.7/")
        except Exception:
            return None

        if response.status_code != 200:
            return None

        data = response.json()
        offers = data.get("offers", []) if isinstance(data, dict) else []
        if not offers:
            return None

        first_offer = offers[0]
        if isinstance(first_offer, dict):
            return first_offer.get("current")
        return None

    def check(self, url: str, enable_active_checks: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "not_wordpress",
            "is_wordpress": False,
            "detection_methods": [],
            "version": {"detected": None, "latest": None, "outdated": False, "source": None},
            "plugins": [],
            "themes": [],
            "issues": [],
            "recommendations": [],
            "endpoints": {},
            "wpscan": {"status": "disabled", "issues": []},
            "score": 100,
        }

        try:
            response = self._get(url)
        except Exception as exc:
            return {
                **result,
                "status": "error",
                "issues": [
                    {
                        "name": "WordPress scan failed",
                        "severity": "Medium",
                        "evidence": str(exc),
                    }
                ],
                "recommendations": ["Confirm the target is reachable before running WordPress checks."],
                "score": 0,
            }

        html = response.text or ""
        parsed_url = urlparse(response.url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Support subdirectory installs — strip trailing filename if present
        url_path = parsed_url.path.rstrip("/")
        if "." in url_path.split("/")[-1]:
            url_path = "/".join(url_path.split("/")[:-1])
        site_base = f"{origin}{url_path}".rstrip("/")

        soup = BeautifulSoup(html, "html.parser")

        if "/wp-content/" in html or "/wp-includes/" in html:
            result["detection_methods"].append("asset_paths")

        api_link = soup.find("link", attrs={"rel": re.compile("https://api.w.org/", re.IGNORECASE)})
        if api_link and api_link.get("href"):
            result["detection_methods"].append("api_link")
            result["endpoints"]["api_link"] = api_link["href"]

        version, version_source = self._extract_version_from_html(html)
        if version:
            result["detection_methods"].append(version_source or "version_signal")
            result["version"]["detected"] = version
            result["version"]["source"] = version_source

        # Check wp-json at the subdirectory path first, fall back to root
        for wp_json_url in [f"{site_base}/wp-json/", f"{origin}/wp-json/"]:
            try:
                wp_json_response = self._get(wp_json_url)
                if wp_json_response.status_code == 200:
                    wp_json_data = wp_json_response.json()
                    namespaces = wp_json_data.get("namespaces", []) if isinstance(wp_json_data, dict) else []
                    if "wp/v2" in namespaces:
                        result["detection_methods"].append("wp_json")
                        result["endpoints"]["wp_json"] = wp_json_url
                        site_base = wp_json_url.rstrip("/wp-json/").rstrip("/")
                        break
            except Exception:
                pass

        result["detection_methods"] = list(dict.fromkeys(result["detection_methods"]))
        result["is_wordpress"] = bool(result["detection_methods"])
        if not result["is_wordpress"]:
            return result

        result["status"] = "detected"
        if settings.external_tools_enabled and settings.wpscan_enabled and not enable_active_checks:
            result["wpscan"] = {
                "enabled": False,
                "status": "not_authorized",
                "issues": [],
                "summary": "WPScan requires verified target ownership and active checks.",
            }
        elif settings.external_tools_enabled and settings.wpscan_enabled:
            result["wpscan"] = self.wpscan.scan(url)
            for issue in result["wpscan"].get("issues", []) or []:
                result["issues"].append(issue)
            if result["wpscan"].get("issues"):
                result["recommendations"].append("Review WPScan findings and patch affected WordPress core, plugin, or theme components.")

        result["plugins"] = self._detect_plugins(html, site_base)
        result["themes"] = self._detect_themes(html)

        latest_core = self._latest_core_version()
        result["version"]["latest"] = latest_core
        detected_core = result["version"]["detected"]
        if detected_core and latest_core and compare_versions(detected_core, latest_core) < 0:
            result["version"]["outdated"] = True
            result["issues"].append(
                {
                    "name": "Outdated WordPress core version",
                    "severity": "High",
                    "evidence": f"Detected {detected_core}; latest available is {latest_core}.",
                }
            )
            result["recommendations"].append(
                "Update WordPress core to the latest supported security release."
            )

        if detected_core:
            result["issues"].append(
                {
                    "name": "WordPress version exposed",
                    "severity": "Low",
                    "evidence": f"Version {detected_core} exposed via {result['version'].get('source')}.",
                }
            )
            result["recommendations"].append(
                "Reduce public WordPress version exposure in generator tags and public files."
            )

        for plugin in result["plugins"]:
            repo_info = self._plugin_repo_info(plugin["slug"])
            if repo_info:
                plugin.update(repo_info)
                installed_version = plugin.get("version")
                latest_version = plugin.get("latest_version")
                if installed_version and latest_version and compare_versions(installed_version, latest_version) < 0:
                    plugin["outdated"] = True
                    result["issues"].append(
                        {
                            "name": "Outdated WordPress plugin",
                            "severity": "High",
                            "evidence": (
                                f"{plugin['slug']} appears to be {installed_version}; "
                                f"latest available is {latest_version}."
                            ),
                        }
                    )
                    result["recommendations"].append(
                        "Update installed WordPress plugins to their latest supported versions."
                    )
                else:
                    plugin["outdated"] = False

        readme_url = f"{site_base}/readme.html"
        readme_status, _, readme_text = self._get_text(readme_url)
        result["endpoints"]["readme"] = {"url": readme_url, "status_code": readme_status}
        if readme_status == 200 and "wordpress" in readme_text.lower():
            result["issues"].append(
                {
                    "name": "Public WordPress readme exposed",
                    "severity": "Low",
                    "evidence": readme_url,
                }
            )
            result["recommendations"].append(
                "Restrict or remove public access to readme.html on production WordPress sites."
            )

        xmlrpc_url = f"{site_base}/xmlrpc.php"
        xmlrpc_status, _, xmlrpc_text = self._get_text(xmlrpc_url)
        result["endpoints"]["xmlrpc"] = {"url": xmlrpc_url, "status_code": xmlrpc_status}
        if xmlrpc_status in {200, 405} and "xml-rpc" in xmlrpc_text.lower():
            result["issues"].append(
                {
                    "name": "XML-RPC endpoint exposed",
                    "severity": "Medium",
                    "evidence": f"{xmlrpc_url} responded with status {xmlrpc_status}.",
                }
            )
            result["recommendations"].append(
                "Disable or aggressively rate-limit XML-RPC if the site does not need it."
            )

        users_url = f"{site_base}/wp-json/wp/v2/users?per_page=5&_fields=id,slug,name"
        try:
            users_response = self._get(users_url)
            result["endpoints"]["users_api"] = {"url": users_url, "status_code": users_response.status_code}
            if users_response.status_code == 200:
                users_data = users_response.json()
                if isinstance(users_data, list) and users_data:
                    sample_users = ", ".join(
                        str(user.get("slug") or user.get("name") or user.get("id"))
                        for user in users_data[:3]
                    )
                    result["issues"].append(
                        {
                            "name": "Public WordPress user enumeration",
                            "severity": "Medium",
                            "evidence": f"User data exposed via REST API: {sample_users}",
                        }
                    )
                    result["recommendations"].append(
                        "Restrict public user enumeration through the WordPress REST API."
                    )
        except Exception:
            pass

        debug_log_url = f"{site_base}/wp-content/debug.log"
        debug_status, _, debug_text = self._get_text(debug_log_url)
        result["endpoints"]["debug_log"] = {"url": debug_log_url, "status_code": debug_status}
        if debug_status == 200 and debug_text.strip():
            result["issues"].append(
                {
                    "name": "Public WordPress debug log exposed",
                    "severity": "High",
                    "evidence": debug_log_url,
                }
            )
            result["recommendations"].append(
                "Disable public access to wp-content/debug.log and review logged secrets or stack traces."
            )

        uploads_url = f"{site_base}/wp-content/uploads/"
        uploads_status, _, uploads_text = self._get_text(uploads_url)
        result["endpoints"]["uploads"] = {"url": uploads_url, "status_code": uploads_status}
        if uploads_status == 200 and INDEX_OF_RE.search(uploads_text):
            result["issues"].append(
                {
                    "name": "Directory listing enabled on uploads",
                    "severity": "Medium",
                    "evidence": uploads_url,
                }
            )
            result["recommendations"].append(
                "Disable directory listing on wp-content/uploads and other public content directories."
            )

        deduped_recommendations = []
        seen = set()
        for recommendation in result["recommendations"]:
            if recommendation not in seen:
                seen.add(recommendation)
                deduped_recommendations.append(recommendation)
        result["recommendations"] = deduped_recommendations

        issue_penalty = 12 * len(result["issues"])
        result["score"] = max(0, 100 - issue_penalty)
        result["status"] = "issues_found" if result["issues"] else "detected"
        return result
