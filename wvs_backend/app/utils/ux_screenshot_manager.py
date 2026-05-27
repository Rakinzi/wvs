from __future__ import annotations

import hashlib
import os
from urllib.parse import urlparse

from app.settings import settings


def ensure_screenshot_dir() -> str:
    screenshot_dir = settings.ux_scan_screenshot_dir
    os.makedirs(screenshot_dir, exist_ok=True)
    return screenshot_dir


def build_screenshot_filename(page_url: str, viewport: str) -> str:
    parsed = urlparse(page_url)
    fingerprint = hashlib.sha1(f"{page_url}|{viewport}".encode("utf-8")).hexdigest()[:12]
    host = (parsed.netloc or "target").replace(":", "_")
    return f"{host}_{viewport}_{fingerprint}.png"


def capture_page_screenshot(page, page_url: str, viewport: str) -> str:
    screenshot_dir = ensure_screenshot_dir()
    path = os.path.join(screenshot_dir, build_screenshot_filename(page_url, viewport))
    page.screenshot(path=path, full_page=False)
    return os.path.abspath(path)


def collect_screenshot_paths(data) -> set[str]:
    found: set[str] = set()

    def walk(value):
        if isinstance(value, dict):
            # evidence.screenshot_path (UX/visual AI findings)
            evidence = value.get("evidence")
            if isinstance(evidence, dict):
                path = evidence.get("screenshot_path")
                if isinstance(path, str) and path:
                    found.add(path)
            # screenshots.screenshots.{desktop,mobile} (screenshot scanner)
            shots = value.get("screenshots")
            if isinstance(shots, dict):
                for path in shots.values():
                    if isinstance(path, str) and path:
                        found.add(path)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(data)
    return found
