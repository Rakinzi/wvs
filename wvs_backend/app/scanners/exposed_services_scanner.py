from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx

from app.settings import settings
from app.scanners.external_tooling import NmapRunner
from app.utils.finding_normalizer import normalize_ux_findings
from app.utils.remediation_prompts import build_builder_prompt
from app.utils.scan_helpers import normalize_target_url
from app.utils.ux_scan_helpers import ux_finding_defaults


class ExposedServicesScanner:
    HIGH_RISK_PORTS = {
        3306: ("MySQL", "Database service should not be directly reachable from the public internet."),
        5432: ("PostgreSQL", "Database service should not be directly reachable from the public internet."),
        6379: ("Redis", "Redis exposure can lead to data theft or remote command abuse."),
        27017: ("MongoDB", "MongoDB should be private or access-controlled behind a trusted network boundary."),
        9200: ("Elasticsearch", "Elasticsearch exposure can leak indexes and operational data."),
        3389: ("RDP", "Remote desktop should not be broadly exposed on launch targets."),
    }
    MEDIUM_RISK_PORTS = {
        22: "SSH is reachable; confirm key-only access, hardened users, and allowlisting.",
        2222: "Alternate SSH/admin port is reachable; confirm it is intentional.",
        3000: "Common development server port is reachable.",
        5000: "Common Flask/API development port is reachable.",
        5173: "Common Vite development server port is reachable.",
        8000: "Common development/admin server port is reachable.",
        8080: "Non-standard web service is reachable.",
        8443: "Non-standard HTTPS service is reachable.",
        1025: "Common local mail catcher SMTP port is reachable.",
        8025: "Common local mail catcher web UI port is reachable.",
    }
    HTTP_LIKE_PORTS = {80, 443, 3000, 5000, 5173, 8000, 8080, 8443, 9200, 8025}

    def __init__(self):
        self.nmap = NmapRunner(settings.nmap_cli_path, settings.external_tools_timeout_seconds)

    def _ports(self, explicit_ports: list[int] | None = None) -> list[int]:
        raw_ports = explicit_ports or [
            int(item.strip())
            for item in settings.exposed_services_ports.split(",")
            if item.strip().isdigit()
        ]
        seen: set[int] = set()
        ports: list[int] = []
        for port in raw_ports:
            if port < 1 or port > 65535 or port in seen:
                continue
            seen.add(port)
            ports.append(port)
            if len(ports) >= settings.exposed_services_max_ports:
                break
        return ports

    async def _connect_port(self, hostname: str, port: int) -> dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port),
                timeout=settings.exposed_services_timeout_seconds,
            )
            writer.close()
            await writer.wait_closed()
            return {"port": port, "open": True}
        except (TimeoutError, OSError, ssl.SSLError):
            return {"port": port, "open": False}

    async def _scan_ports(self, hostname: str, ports: list[int]) -> list[dict[str, Any]]:
        return await asyncio.gather(*(self._connect_port(hostname, port) for port in ports))

    def _probe_http(self, hostname: str, scheme: str, port: int) -> dict[str, Any]:
        if port not in self.HTTP_LIKE_PORTS:
            return {}
        candidates = []
        if port == 443 or port == 8443:
            candidates.append(f"https://{hostname}:{port}")
        elif port == 80:
            candidates.append(f"http://{hostname}")
        else:
            candidates.extend([f"http://{hostname}:{port}", f"https://{hostname}:{port}"])

        with httpx.Client(timeout=3, follow_redirects=False, verify=False) as client:
            for candidate in candidates:
                try:
                    response = client.get(candidate, headers={"User-Agent": "WVS-ExposedServices/1.0"})
                except httpx.HTTPError:
                    continue
                server = response.headers.get("server", "")
                powered = response.headers.get("x-powered-by", "")
                body_sample = response.text[:400].lower()
                hints = []
                if "vite" in body_sample or "vite" in server.lower():
                    hints.append("vite")
                if "flask" in server.lower() or "werkzeug" in server.lower():
                    hints.append("flask")
                if "elasticsearch" in body_sample:
                    hints.append("elasticsearch")
                return {
                    "url": candidate,
                    "status_code": response.status_code,
                    "server": server,
                    "x_powered_by": powered,
                    "hints": hints,
                }
        return {}

    def _issue_for_service(self, target_url: str, service: dict[str, Any]) -> dict[str, Any] | None:
        port = int(service["port"])
        banner = service.get("http") or {}
        if port in self.HIGH_RISK_PORTS:
            name, risk = self.HIGH_RISK_PORTS[port]
            severity = "high"
            title = f"{name} service is publicly reachable"
            remediation = f"Move {name} behind a private network, firewall, VPN, or managed private endpoint before launch."
        elif port in self.MEDIUM_RISK_PORTS:
            severity = "medium"
            title = "Non-standard or administrative service is publicly reachable"
            risk = self.MEDIUM_RISK_PORTS[port]
            remediation = "Confirm this service is intentional, remove development servers, and restrict admin services by firewall or allowlist."
        elif port in {80, 443}:
            return None
        else:
            severity = "low"
            title = "Unexpected public TCP service is reachable"
            risk = "Unexpected open services increase launch attack surface."
            remediation = "Close unused ports and expose only services required for the public application."

        hints = ", ".join(banner.get("hints") or [])
        evidence_bits = [f"TCP port {port} accepted a connection."]
        if banner.get("url"):
            evidence_bits.append(f"HTTP probe {banner.get('url')} returned {banner.get('status_code')}.")
        if banner.get("server"):
            evidence_bits.append(f"Server: {banner.get('server')}.")
        if banner.get("x_powered_by"):
            evidence_bits.append(f"X-Powered-By: {banner.get('x_powered_by')}.")
        if hints:
            evidence_bits.append(f"Hints: {hints}.")

        issue = ux_finding_defaults(
            "exposed_services",
            "Exposed Services",
            target_url,
            "network",
            title=title,
            severity=severity,
            confidence="measured",
            evidence={
                "rule_id": "public-service-exposed",
                "description": " ".join(evidence_bits),
                "metric": "open_port",
                "value": port,
                "threshold": "public-web-only",
            },
            user_impact=risk,
            technical_remediation=remediation,
            references=[],
        )
        issue["builder_prompt"] = build_builder_prompt(issue)
        return issue

    def scan(self, url: str, ports: list[int] | None = None) -> dict[str, Any]:
        if not settings.exposed_services_enabled:
            return {"status": "disabled", "issues": [], "recommendations": [], "score": None}

        normalized = normalize_target_url(url)
        parsed = urlparse(normalized)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid target hostname")

        # Resolve once first so obvious DNS failures are explicit in the result.
        try:
            socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return {
                "status": "error",
                "issues": [],
                "open_services": [],
                "recommendations": ["Target hostname could not be resolved for exposed-service checks."],
                "score": None,
            }

        selected_ports = self._ports(ports)
        results = asyncio.run(self._scan_ports(hostname, selected_ports))
        open_services: list[dict[str, Any]] = []
        for result in results:
            if not result.get("open"):
                continue
            port = int(result["port"])
            service = {
                "host": hostname,
                "port": port,
                "protocol": "tcp",
                "risk": "high" if port in self.HIGH_RISK_PORTS else "medium" if port in self.MEDIUM_RISK_PORTS else "informational",
                "http": self._probe_http(hostname, parsed.scheme, port),
            }
            open_services.append(service)

        raw_issues = [
            issue
            for issue in (self._issue_for_service(normalized, service) for service in open_services)
            if issue is not None
        ]
        nmap_result = {"status": "disabled", "issues": [], "open_services": []}
        if settings.external_tools_enabled and settings.nmap_enabled:
            nmap_result = self.nmap.scan(normalized, ports=selected_ports)
            seen_ports = {int(service["port"]) for service in open_services}
            for service in nmap_result.get("open_services", []) or []:
                port = int(service.get("port") or 0)
                if port and port not in seen_ports:
                    open_services.append(service)
                    seen_ports.add(port)
            for issue in nmap_result.get("issues", []) or []:
                raw_issues.append(
                    ux_finding_defaults(
                        "exposed_services",
                        "Exposed Services",
                        normalized,
                        "network",
                        title=issue.get("name") or "Public service detected by nmap",
                        severity=str(issue.get("severity") or "medium").lower(),
                        confidence="measured",
                        evidence={
                            "rule_id": "nmap-public-service",
                            "description": issue.get("evidence") or "nmap detected a reachable service.",
                            "metric": "open_port",
                            "value": issue.get("port"),
                            "threshold": "public-web-only",
                        },
                        user_impact="Unexpected reachable services increase the target attack surface.",
                        technical_remediation="Close unused ports and restrict administrative or data services to trusted networks.",
                        references=["nmap service/version detection"],
                    )
                )
        issues = normalize_ux_findings(raw_issues, default_scanner="exposed_services", default_category="Exposed Services")
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "open_services": open_services,
            "ports_checked": selected_ports,
            "nmap": nmap_result,
            "recommendations": [
                "Expose only required public web ports and place databases, caches, admin tools, and dev servers behind private network controls.",
                "Remove Vite/Flask/Next development servers before launch and verify firewall rules from outside the deployment network.",
            ] if issues else [],
            "score": max(0, 100 - len([item for item in issues if item.get("severity") in {"high", "medium"}]) * 12),
        }
