from __future__ import annotations

from urllib.parse import urljoin, urlparse

from app.settings import settings
from app.utils.scan_helpers import normalize_target_url


DEFAULT_VIEWPORTS = {
    "mobile": {"width": settings.ux_scan_mobile_width, "height": settings.ux_scan_mobile_height},
    "desktop": {"width": settings.ux_scan_desktop_width, "height": settings.ux_scan_desktop_height},
}


def build_page_targets(base_url: str, page_paths: list[str] | None = None) -> list[str]:
    normalized = normalize_target_url(base_url)
    parsed = urlparse(normalized)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    requested = page_paths or [""]
    urls: list[str] = []
    seen: set[str] = set()

    for path in requested:
        candidate = normalize_target_url(urljoin(origin + "/", path or ""))
        if urlparse(candidate).netloc != parsed.netloc:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        urls.append(candidate)
        if len(urls) >= min(settings.ux_scan_max_pages, 10):
            break

    if not urls:
        urls.append(normalized)
    return urls


def ux_finding_defaults(scanner: str, category: str, page_url: str, viewport: str, **extra):
    return {
        "scanner": scanner,
        "category": category,
        "page_url": page_url,
        "viewport": viewport,
        **extra,
    }
