from __future__ import annotations

from typing import Any

from app.settings import settings


class ClamAVService:
    def __init__(self) -> None:
        self.enabled = settings.clamav_enabled

    def _client(self):
        if not self.enabled:
            return None
        try:
            import clamd
        except Exception:
            return None

        if settings.clamav_unix_socket:
            return clamd.ClamdUnixSocket(path=settings.clamav_unix_socket)
        if settings.clamav_network_socket:
            host, _, raw_port = settings.clamav_network_socket.partition(":")
            port = int(raw_port or "3310")
            return clamd.ClamdNetworkSocket(host=host, port=port)
        return None

    def scan_file(self, path: str) -> dict[str, Any]:
        client = self._client()
        if client is None:
            return {
                "enabled": self.enabled,
                "status": "unavailable" if self.enabled else "disabled",
                "matched": False,
                "signature": None,
            }

        try:
            result = client.scan(path) or {}
            entry = next(iter(result.values()), None)
            if not entry:
                return {"enabled": True, "status": "ok", "matched": False, "signature": None}
            state, signature = entry
            matched = str(state).upper() == "FOUND"
            return {
                "enabled": True,
                "status": "ok",
                "matched": matched,
                "signature": signature if matched else None,
            }
        except Exception as exc:
            return {
                "enabled": True,
                "status": "error",
                "matched": False,
                "signature": None,
                "error": str(exc),
            }

