from __future__ import annotations

from typing import Any

from app.scanners.external_tooling import NiktoRunner, disabled_result
from app.settings import settings


class NiktoScanner:
    def __init__(self):
        self.runner = NiktoRunner(settings.nikto_cli_path, settings.external_tools_timeout_seconds)

    def scan(self, url: str, enable_active_checks: bool = False) -> dict[str, Any]:
        if not enable_active_checks:
            return {
                "enabled": False,
                "status": "not_authorized",
                "issues": [],
                "summary": "Nikto requires verified target ownership and active checks.",
            }

        if not settings.external_tools_enabled or not settings.nikto_enabled:
            return disabled_result("Nikto")
        return self.runner.scan(url)
