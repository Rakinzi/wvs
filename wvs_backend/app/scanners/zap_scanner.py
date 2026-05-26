from __future__ import annotations

import socket
from typing import Any

from zapv2 import ZAPv2

from app.settings import settings


class ZAPScanner:
    def __init__(self):
        self.enabled = settings.zap_enabled
        self.base_url = settings.zap_base_url
        self.api_key = settings.zap_api_key
        self.spider_minutes = settings.zap_spider_max_minutes
        self.active_minutes = settings.zap_active_scan_max_minutes
        self.client = None
        if self.enabled:
            proxies = {
                "http": self.base_url,
                "https": self.base_url,
            }
            self.client = ZAPv2(apikey=self.api_key or None, proxies=proxies)

    def _zap_reachable(self) -> bool:
        from urllib.parse import urlparse
        parsed = urlparse(self.base_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 8080
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            return False

    def _status(self):
        return self.client.core.version

    def scan(self, url: str) -> dict[str, Any]:
        if not self.enabled or self.client is None:
            return {
                "enabled": False,
                "status": "disabled",
                "issues": [],
                "alerts": [],
                "summary": "ZAP integration is installed but not enabled.",
            }

        try:
            if not self._zap_reachable():
                return {
                    "enabled": True,
                    "status": "unavailable",
                    "issues": [],
                    "alerts": [],
                    "summary": f"ZAP is not running at {self.base_url}",
                }
            self._status()
            self.client.urlopen(url)
            spider_id = self.client.spider.scan(url)
            active_scan_id = None
            try:
                self.client.spider.status(spider_id)
                active_scan_id = self.client.ascan.scan(url)
                self.client.ascan.status(active_scan_id)
            except Exception:
                active_scan_id = None

            alerts = self.client.core.alerts(baseurl=url)[:20]
            issues = [
                {
                    "name": alert.get("alert"),
                    "severity": alert.get("risk"),
                    "evidence": alert.get("evidence") or alert.get("description"),
                    "solution": alert.get("solution"),
                    "reference": alert.get("reference"),
                }
                for alert in alerts
            ]

            return {
                "enabled": True,
                "status": "ok",
                "spider_id": spider_id,
                "active_scan_id": active_scan_id,
                "issues": issues,
                "alerts": alerts,
                "summary": f"Collected {len(alerts)} ZAP alerts",
            }
        except Exception as exc:
            return {
                "enabled": True,
                "status": "error",
                "issues": [
                    {
                        "name": "ZAP scan failed",
                        "severity": "Info",
                        "evidence": str(exc),
                    }
                ],
                "alerts": [],
                "summary": str(exc),
            }
