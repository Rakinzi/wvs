from __future__ import annotations

import shlex
import socket
import subprocess
import time
from typing import Any

from zapv2 import ZAPv2

from app.settings import settings

_zap_process: subprocess.Popen | None = None


class ZAPScanner:
    def __init__(self):
        self.enabled = settings.zap_enabled
        self.base_url = settings.zap_base_url
        self.api_key = settings.zap_api_key
        self.spider_minutes = settings.zap_spider_max_minutes
        self.active_minutes = settings.zap_active_scan_max_minutes
        self.auto_start = settings.zap_auto_start
        self.start_cmd = settings.zap_start_cmd
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

    def _try_auto_start(self) -> bool:
        global _zap_process
        if not self.auto_start or not self.start_cmd:
            return False
        if _zap_process is not None and _zap_process.poll() is None:
            # already launched by a previous scan in this worker
            pass
        else:
            try:
                _zap_process = subprocess.Popen(
                    shlex.split(self.start_cmd),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                return False

        # wait up to 60 s for ZAP to become reachable
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self._zap_reachable():
                return True
            time.sleep(3)
        return False

    def _status(self):
        return self.client.core.version

    def _wait_for_completion(self, status_reader, scan_id: str, timeout_seconds: int) -> tuple[bool, int]:
        deadline = time.monotonic() + max(timeout_seconds, 5)
        last_percent = 0

        while time.monotonic() < deadline:
            try:
                raw_status = status_reader(scan_id)
                last_percent = int(raw_status)
            except Exception:
                break

            if last_percent >= 100:
                return True, 100
            time.sleep(2)

        return False, last_percent

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
                if not self._try_auto_start():
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
            spider_completed, spider_percent = self._wait_for_completion(
                self.client.spider.status,
                spider_id,
                self.spider_minutes * 60,
            )

            active_scan_id = None
            active_completed = False
            active_percent = 0
            try:
                active_scan_id = self.client.ascan.scan(url)
                active_completed, active_percent = self._wait_for_completion(
                    self.client.ascan.status,
                    active_scan_id,
                    self.active_minutes * 60,
                )
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

            if not spider_completed or (active_scan_id and not active_completed):
                timeout_parts = []
                if not spider_completed:
                    timeout_parts.append(f"spider stopped at {spider_percent}%")
                if active_scan_id and not active_completed:
                    timeout_parts.append(f"active scan stopped at {active_percent}%")
                summary = "ZAP scan timed out before completion: " + ", ".join(timeout_parts)
                return {
                    "enabled": True,
                    "status": "timeout",
                    "spider_id": spider_id,
                    "active_scan_id": active_scan_id,
                    "issues": issues,
                    "alerts": alerts,
                    "summary": summary,
                    "recommendations": [
                        "Increase ZAP scan time limits if deeper crawling is required.",
                        "Reduce the target scope or run ZAP separately for a longer audit.",
                    ],
                }

            return {
                "enabled": True,
                "status": "ok",
                "spider_id": spider_id,
                "active_scan_id": active_scan_id,
                "spider_completed": spider_completed,
                "active_scan_completed": active_completed,
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
