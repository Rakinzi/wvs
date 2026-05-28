from __future__ import annotations

import socket

from app.scanners.exposed_services_scanner import ExposedServicesScanner
from app.utils.scan_helpers import build_scan_sections, build_scan_summary


def test_exposed_services_reports_high_risk_database_port(monkeypatch):
    scanner = ExposedServicesScanner()

    async def fake_scan_ports(hostname, ports):
        return [{"port": port, "open": port == 6379} for port in ports]

    monkeypatch.setattr(scanner, "_scan_ports", fake_scan_ports)
    monkeypatch.setattr(scanner, "_ports", lambda ports=None: [80, 6379])
    monkeypatch.setattr(scanner, "_probe_http", lambda hostname, scheme, port: {})
    monkeypatch.setattr(
        "app.utils.scan_helpers.socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr(
        "app.scanners.exposed_services_scanner.socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )

    result = scanner.scan("https://example.com")

    assert result["status"] == "issues_found"
    assert result["open_services"][0]["port"] == 6379
    assert result["issues"][0]["severity"] == "high"
    assert "Redis" in result["issues"][0]["title"]


def test_exposed_services_http_probe_flags_dev_server(monkeypatch):
    scanner = ExposedServicesScanner()

    async def fake_scan_ports(hostname, ports):
        return [{"port": port, "open": port == 5173} for port in ports]

    monkeypatch.setattr(scanner, "_scan_ports", fake_scan_ports)
    monkeypatch.setattr(scanner, "_ports", lambda ports=None: [5173])
    monkeypatch.setattr(scanner, "_probe_http", lambda hostname, scheme, port: {"url": "http://example.com:5173", "status_code": 200, "server": "Vite", "hints": ["vite"]})
    monkeypatch.setattr(
        "app.utils.scan_helpers.socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr(
        "app.scanners.exposed_services_scanner.socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )

    result = scanner.scan("https://example.com")

    assert result["status"] == "issues_found"
    assert result["issues"][0]["severity"] == "medium"
    assert "5173" in result["issues"][0]["evidence"]["description"]


def test_exposed_services_flow_into_summary_and_sections():
    findings = {
        "exposed_services": {
            "status": "issues_found",
            "issues": [
                {
                    "title": "Redis service is publicly reachable",
                    "severity": "high",
                    "confidence": "measured",
                    "evidence": {"description": "TCP port 6379 accepted a connection."},
                }
            ],
            "score": 88,
        }
    }

    summary = build_scan_summary(findings)
    sections = build_scan_sections(findings)

    assert summary["exposed_service_issue_count"] == 1
    assert summary["exposed_service_score"] == 88
    assert summary["launch_blocker_count"] == 1
    assert sections["exposed_services"]["issue_count"] == 1
