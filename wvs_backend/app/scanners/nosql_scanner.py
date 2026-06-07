from __future__ import annotations

from typing import Any

from app.scanners.external_tooling import NoSQLMapRunner
from app.settings import settings


class NoSQLInjectionScanner:
    def __init__(self):
        self.nosqlmap = NoSQLMapRunner(
            settings.nosqlmap_cli_path,
            settings.external_tools_timeout_seconds,
            settings.nosqlmap_command_template,
        )

    def scan(self, url: str, enable_active_checks: bool = False) -> dict[str, Any]:
        if not settings.external_tools_enabled or not settings.nosqlmap_enabled:
            return {
                "status": "disabled",
                "issues": [],
                "recommendations": [],
                "summary": "NoSQLMap external validation is disabled.",
            }
        return self.nosqlmap.scan(url, enabled=enable_active_checks)
