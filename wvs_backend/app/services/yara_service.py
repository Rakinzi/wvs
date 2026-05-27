from __future__ import annotations

from pathlib import Path
from typing import Any

from app.settings import settings


class YaraService:
    def __init__(self) -> None:
        self.enabled = settings.yara_enabled
        self.rules_dir = Path(settings.yara_rules_dir)
        self._compiled_rules = None

    def _compile(self):
        if not self.enabled:
            return None
        if self._compiled_rules is not None:
            return self._compiled_rules
        try:
            import yara
        except Exception:
            return None
        if not self.rules_dir.exists():
            return None
        sources = {
            rule_file.stem: str(rule_file)
            for rule_file in self.rules_dir.glob("*.yar*")
        }
        if not sources:
            return None
        self._compiled_rules = yara.compile(filepaths=sources)
        return self._compiled_rules

    def scan_file(self, path: str) -> dict[str, Any]:
        rules = self._compile()
        if rules is None:
            return {
                "enabled": self.enabled,
                "status": "unavailable" if self.enabled else "disabled",
                "matches": [],
            }
        try:
            matches = rules.match(path)
            return {
                "enabled": True,
                "status": "ok",
                "matches": [
                    {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": list(match.tags or []),
                    }
                    for match in matches
                ],
            }
        except Exception as exc:
            return {
                "enabled": True,
                "status": "error",
                "matches": [],
                "error": str(exc),
            }

