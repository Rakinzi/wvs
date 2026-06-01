from __future__ import annotations

import csv
import json
import shlex
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def tool_available(binary: str | None) -> bool:
    return bool(binary and shutil.which(binary))


def unavailable_result(tool_name: str, binary: str | None) -> dict[str, Any]:
    return {
        "enabled": True,
        "status": "unavailable",
        "issues": [],
        "recommendations": [
            f"Install {tool_name} on the scanner host or backend image to enable this integration."
        ],
        "summary": f"{tool_name} was not found at {binary or 'the configured path'}.",
    }


def disabled_result(tool_name: str) -> dict[str, Any]:
    return {
        "enabled": False,
        "status": "disabled",
        "issues": [],
        "recommendations": [],
        "summary": f"{tool_name} integration is disabled.",
    }


def run_command(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        check=False,
        text=True,
        timeout=max(timeout, 5),
    )


def normalized_origin(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    return f"{scheme}://{netloc}".rstrip("/")


def normalized_hostname(url: str) -> str | None:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or parsed.path.split("/")[0] or None


def text_issue(name: str, severity: str, evidence: str, **extra: Any) -> dict[str, Any]:
    issue = {"name": name, "severity": severity, "evidence": evidence}
    issue.update({key: value for key, value in extra.items() if value is not None})
    return issue


class NmapRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str, ports: list[int] | None = None) -> dict[str, Any]:
        if not tool_available(self.binary):
            return unavailable_result("nmap", self.binary)
        hostname = normalized_hostname(url)
        if not hostname:
            return {"status": "error", "issues": [], "open_services": [], "summary": "Invalid hostname."}

        port_arg = ",".join(str(port) for port in ports) if ports else "T:22,80,443,2222,3000,3306,3389,5000,5173,5432,6379,8000,8080,8443,9200,1025,8025,27017"
        args = [self.binary or "nmap", "-sT", "-sV", "--version-light", "-Pn", "-p", port_arg, "-oX", "-", hostname]
        try:
            proc = run_command(args, self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "issues": [], "open_services": [], "summary": "nmap timed out."}
        except Exception as exc:
            return {"status": "error", "issues": [text_issue("nmap failed", "Low", str(exc))], "open_services": []}

        open_services: list[dict[str, Any]] = []
        issues: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(proc.stdout)
            for port_el in root.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port_el.find("service")
                port = int(port_el.get("portid") or 0)
                service_name = service.get("name") if service is not None else None
                product = service.get("product") if service is not None else None
                version = service.get("version") if service is not None else None
                open_services.append(
                    {
                        "host": hostname,
                        "port": port,
                        "protocol": port_el.get("protocol"),
                        "service": service_name,
                        "product": product,
                        "version": version,
                    }
                )
                if port not in {80, 443}:
                    severity = "High" if port in {3306, 5432, 6379, 27017, 9200, 3389} else "Medium"
                    evidence = f"nmap found {port}/{port_el.get('protocol')} open"
                    if service_name:
                        evidence += f" ({service_name})"
                    if product or version:
                        evidence += f": {' '.join(part for part in [product, version] if part)}"
                    issues.append(text_issue("Public service detected by nmap", severity, evidence))
        except ET.ParseError:
            return {
                "status": "error",
                "issues": [text_issue("nmap output could not be parsed", "Low", proc.stderr or proc.stdout[:500])],
                "open_services": [],
                "raw": proc.stdout[:2000],
            }

        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "open_services": open_services,
            "recommendations": [
                "Expose only required public ports and move databases, caches, admin panels, and dev servers behind private network controls."
            ] if issues else [],
            "summary": f"nmap found {len(open_services)} open service(s).",
            "command": shlex.join(args),
        }


class NiktoRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str) -> dict[str, Any]:
        if not tool_available(self.binary):
            return unavailable_result("Nikto", self.binary)
        target = normalized_origin(url)
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "nikto.csv"
            args = [self.binary or "nikto", "-host", target, "-Format", "csv", "-output", str(output_path), "-nointeractive"]
            try:
                proc = run_command(args, self.timeout)
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "issues": [], "summary": "Nikto timed out."}
            except Exception as exc:
                return {"status": "error", "issues": [text_issue("Nikto failed", "Low", str(exc))]}

            rows: list[list[str]] = []
            if output_path.exists():
                rows = list(csv.reader(output_path.read_text(errors="ignore").splitlines()))
            issues = []
            for row in rows:
                if len(row) < 8 or row[0].lower().startswith("host"):
                    continue
                message = row[-1].strip()
                if not message:
                    continue
                issues.append(text_issue("Nikto web server finding", "Medium", message, path=row[6] if len(row) > 6 else None))
            if not issues and proc.stderr:
                summary = proc.stderr.strip()[:500]
            else:
                summary = f"Nikto returned {len(issues)} finding(s)."
            return {
                "status": "issues_found" if issues else "ok",
                "issues": issues[:50],
                "recommendations": ["Review Nikto findings and patch exposed web server files, defaults, and misconfigurations."] if issues else [],
                "summary": summary,
            }


class WhatWebRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str) -> dict[str, Any]:
        if not tool_available(self.binary):
            return unavailable_result("WhatWeb", self.binary)
        args = [self.binary or "whatweb", "--log-json=-", "--no-errors", normalized_origin(url)]
        try:
            proc = run_command(args, self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "plugins": {}, "issues": [], "summary": "WhatWeb timed out."}
        except Exception as exc:
            return {"status": "error", "plugins": {}, "issues": [text_issue("WhatWeb failed", "Low", str(exc))]}

        plugins: dict[str, Any] = {}
        try:
            data = json.loads(proc.stdout or "[]")
            if isinstance(data, list) and data:
                plugins = data[0].get("plugins") or {}
        except json.JSONDecodeError:
            pass
        return {
            "status": "ok",
            "plugins": plugins,
            "issues": [],
            "summary": f"WhatWeb identified {len(plugins)} plugin signature(s).",
        }


class Wafw00fRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str) -> dict[str, Any]:
        if not tool_available(self.binary):
            return unavailable_result("wafw00f", self.binary)
        args = [self.binary or "wafw00f", "-f", "json", normalized_origin(url)]
        try:
            proc = run_command(args, self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "issues": [], "summary": "wafw00f timed out."}
        except Exception as exc:
            return {"status": "error", "issues": [text_issue("wafw00f failed", "Low", str(exc))]}
        detected: list[str] = []
        try:
            data = json.loads(proc.stdout or "{}")
            entries = data if isinstance(data, list) else [data]
            for entry in entries:
                if isinstance(entry, dict) and entry.get("detected"):
                    detected.extend(entry.get("firewall") or [])
        except json.JSONDecodeError:
            pass
        issues = [] if detected else [text_issue("No WAF detected", "Info", "wafw00f did not identify a web application firewall.")]
        return {
            "status": "ok" if detected else "informational",
            "waf_detected": bool(detected),
            "firewalls": detected,
            "issues": issues,
            "recommendations": [] if detected else ["Consider edge protection or WAF rules for high-risk launch targets."],
            "summary": f"Detected WAF: {', '.join(detected)}" if detected else "No WAF detected.",
        }


class SSLScanRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str) -> dict[str, Any]:
        if not tool_available(self.binary):
            return unavailable_result("sslscan", self.binary)
        hostname = normalized_hostname(url)
        if not hostname:
            return {"status": "error", "issues": [], "summary": "Invalid hostname."}
        args = [self.binary or "sslscan", "--no-colour", hostname]
        try:
            proc = run_command(args, self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "issues": [], "summary": "sslscan timed out."}
        except Exception as exc:
            return {"status": "error", "issues": [text_issue("sslscan failed", "Low", str(exc))]}
        output = proc.stdout or ""
        issues = []
        for marker, severity in [("SSLv2", "Critical"), ("SSLv3", "Critical"), ("TLSv1.0", "High"), ("TLSv1.1", "High"), ("RC4", "High"), ("3DES", "High")]:
            if marker in output and "enabled" in output.lower():
                issues.append(text_issue(f"Weak TLS support reported by sslscan: {marker}", severity, marker))
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "raw_summary": "\n".join(output.splitlines()[:80]),
            "summary": f"sslscan returned {len(issues)} weak TLS indicator(s).",
        }


class WPScanRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str, aggressive: bool = False) -> dict[str, Any]:
        if not tool_available(self.binary):
            return unavailable_result("WPScan", self.binary)
        args = [self.binary or "wpscan", "--url", normalized_origin(url), "--format", "json", "--no-banner", "--random-user-agent"]
        if not aggressive:
            args.extend(["--plugins-detection", "passive"])
        try:
            proc = run_command(args, self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "issues": [], "summary": "WPScan timed out."}
        except Exception as exc:
            return {"status": "error", "issues": [text_issue("WPScan failed", "Low", str(exc))]}
        issues = []
        try:
            data = json.loads(proc.stdout or "{}")
            version = data.get("version") or {}
            if version.get("number") and version.get("status") == "outdated":
                issues.append(text_issue("WPScan detected outdated WordPress core", "High", f"Version {version.get('number')} is outdated."))
            for collection_name in ("plugins", "themes"):
                collection = data.get(collection_name) or {}
                for slug, item in collection.items():
                    vulns = item.get("vulnerabilities") or []
                    for vuln in vulns:
                        issues.append(text_issue(f"WPScan vulnerability in {slug}", "High", vuln.get("title") or "Known vulnerability reported by WPScan."))
        except json.JSONDecodeError:
            pass
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues[:50],
            "summary": f"WPScan returned {len(issues)} vulnerability indicator(s).",
        }


class SQLMapRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str, enabled: bool = False) -> dict[str, Any]:
        if not enabled:
            return disabled_result("sqlmap active validation")
        if not tool_available(self.binary):
            return unavailable_result("sqlmap", self.binary)
        args = [self.binary or "sqlmap", "-u", url, "--batch", "--crawl=1", "--level=1", "--risk=1", "--output-dir=/tmp/sqlmap-wvs"]
        try:
            proc = run_command(args, self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "issues": [], "summary": "sqlmap timed out."}
        except Exception as exc:
            return {"status": "error", "issues": [text_issue("sqlmap failed", "Low", str(exc))]}
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        vulnerable = "is vulnerable" in output.lower() or "parameter" in output.lower() and "injectable" in output.lower()
        issues = [text_issue("sqlmap reported injectable parameter", "Critical", "\n".join(output.splitlines()[-20:]))] if vulnerable else []
        return {"status": "issues_found" if issues else "ok", "issues": issues, "summary": "sqlmap active validation completed."}


class FFufRunner:
    def __init__(self, binary: str | None, wordlist: str | None, timeout: int):
        self.binary = binary
        self.wordlist = wordlist
        self.timeout = timeout

    def scan(self, url: str, enabled: bool = False) -> dict[str, Any]:
        if not enabled:
            return disabled_result("ffuf content discovery")
        if not tool_available(self.binary):
            return unavailable_result("ffuf", self.binary)
        if not self.wordlist or not Path(self.wordlist).exists():
            return {
                "enabled": True,
                "status": "unavailable",
                "issues": [],
                "recommendations": ["Configure FFUF_WORDLIST with a small, approved discovery wordlist."],
                "summary": "ffuf wordlist is not configured.",
            }
        target = normalized_origin(url) + "/FUZZ"
        args = [self.binary or "ffuf", "-u", target, "-w", self.wordlist, "-of", "json", "-s", "-mc", "200,204,301,302,307,308,401,403"]
        try:
            proc = run_command(args, self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "issues": [], "summary": "ffuf timed out."}
        except Exception as exc:
            return {"status": "error", "issues": [text_issue("ffuf failed", "Low", str(exc))]}
        results = []
        try:
            data = json.loads(proc.stdout or "{}")
            results = data.get("results") or []
        except json.JSONDecodeError:
            pass
        issues = [
            text_issue("ffuf discovered reachable path", "Info", f"{item.get('url')} returned {item.get('status')}")
            for item in results[:50]
        ]
        return {"status": "informational" if issues else "ok", "issues": issues, "discovered": results[:50], "summary": f"ffuf discovered {len(results)} path(s)."}
