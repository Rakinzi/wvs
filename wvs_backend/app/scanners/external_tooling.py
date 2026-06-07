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
from urllib.parse import parse_qsl, urlparse


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


def command_output(proc: subprocess.CompletedProcess[str]) -> str:
    return "\n".join(
        part.strip()
        for part in [proc.stderr or "", proc.stdout or ""]
        if part.strip()
    )


def command_failure_result(
    tool_name: str,
    proc: subprocess.CompletedProcess[str],
    args: list[str],
    **extra: Any,
) -> dict[str, Any] | None:
    if proc.returncode == 0:
        return None
    output = command_output(proc)
    dependency_error = "Required module not found" in output
    result = {
        "enabled": True,
        "status": "unavailable" if dependency_error else "error",
        "issues": [],
        "recommendations": [
            f"Install missing runtime dependencies for {tool_name} in the scanner image."
            if dependency_error
            else f"Check the {tool_name} installation, command arguments, and scanner host logs."
        ],
        "summary": output[:500] or f"{tool_name} exited with status {proc.returncode}.",
        "command": shlex.join(args),
    }
    result.update(extra)
    return result


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

        failure = command_failure_result("nmap", proc, args, open_services=[])
        if failure:
            return failure

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
            if not issues:
                failure = command_failure_result("Nikto", proc, args)
                if failure:
                    return failure
            stderr = (proc.stderr or "").strip()
            if not issues and "ERROR:" in stderr:
                return {
                    "enabled": True,
                    "status": "error",
                    "issues": [],
                    "recommendations": ["Check Nikto connectivity/TLS handling for this target. Cloudflare or TLS fingerprinting may block Nikto requests."],
                    "summary": stderr[:500],
                    "command": shlex.join(args),
                }
            summary = stderr[:500] if not issues and stderr else f"Nikto returned {len(issues)} finding(s)."
            return {
                "status": "issues_found" if issues else "ok",
                "issues": issues[:50],
                "recommendations": ["Review Nikto findings and patch exposed web server files, defaults, and misconfigurations."] if issues else [],
                "summary": summary,
                "command": shlex.join(args),
            }


class WhatWebRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str) -> dict[str, Any]:
        if not tool_available(self.binary):
            return unavailable_result("WhatWeb", self.binary)
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "whatweb.json"
            args = [self.binary or "whatweb", f"--log-json={output_path}", "--quiet", "--no-errors", normalized_origin(url)]
            try:
                proc = run_command(args, self.timeout)
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "plugins": {}, "issues": [], "summary": "WhatWeb timed out."}
            except Exception as exc:
                return {"status": "error", "plugins": {}, "issues": [text_issue("WhatWeb failed", "Low", str(exc))]}

            failure = command_failure_result("WhatWeb", proc, args, plugins={})
            if failure:
                return failure

            plugins: dict[str, Any] = {}
            try:
                data = json.loads(output_path.read_text(errors="ignore") if output_path.exists() else "[]")
                if isinstance(data, list) and data:
                    plugins = data[0].get("plugins") or {}
            except json.JSONDecodeError:
                return {
                    "status": "error",
                    "plugins": {},
                    "issues": [text_issue("WhatWeb output could not be parsed", "Low", command_output(proc)[:500])],
                    "summary": "WhatWeb returned invalid JSON output.",
                    "command": shlex.join(args),
                }
        return {
            "status": "ok",
            "plugins": plugins,
            "issues": [],
            "summary": f"WhatWeb identified {len(plugins)} plugin signature(s).",
            "command": shlex.join(args),
        }


class Wafw00fRunner:
    def __init__(self, binary: str | None, timeout: int):
        self.binary = binary
        self.timeout = timeout

    def scan(self, url: str) -> dict[str, Any]:
        if not tool_available(self.binary):
            return unavailable_result("wafw00f", self.binary)
        args = [self.binary or "wafw00f", "-f", "json", "-o", "-", "--no-colors", normalized_origin(url)]
        try:
            proc = run_command(args, self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "issues": [], "summary": "wafw00f timed out."}
        except Exception as exc:
            return {"status": "error", "issues": [text_issue("wafw00f failed", "Low", str(exc))]}

        failure = command_failure_result("wafw00f", proc, args)
        if failure:
            return failure

        detected: list[str] = []
        try:
            data = json.loads(proc.stdout or "{}")
            entries = data if isinstance(data, list) else [data]
            for entry in entries:
                if isinstance(entry, dict) and entry.get("detected"):
                    firewall = entry.get("firewall")
                    if isinstance(firewall, list):
                        detected.extend(str(item) for item in firewall)
                    elif firewall:
                        detected.append(str(firewall))
        except json.JSONDecodeError:
            return {
                "status": "error",
                "issues": [text_issue("wafw00f output could not be parsed", "Low", command_output(proc)[:500])],
                "summary": "wafw00f returned invalid JSON output.",
                "command": shlex.join(args),
            }
        issues = [] if detected else [text_issue("No WAF detected", "Info", "wafw00f did not identify a web application firewall.")]
        return {
            "status": "ok" if detected else "informational",
            "waf_detected": bool(detected),
            "firewalls": detected,
            "issues": issues,
            "recommendations": [] if detected else ["Consider edge protection or WAF rules for high-risk launch targets."],
            "summary": f"Detected WAF: {', '.join(detected)}" if detected else "No WAF detected.",
            "command": shlex.join(args),
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

        failure = command_failure_result("sslscan", proc, args)
        if failure:
            return failure

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
            "command": shlex.join(args),
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
            scan_aborted = str(data.get("scan_aborted") or "")
            if proc.returncode != 0 and "does not seem to be running WordPress" in scan_aborted:
                return {
                    "status": "informational",
                    "issues": [],
                    "summary": "WPScan completed: target does not appear to be running WordPress.",
                    "command": shlex.join(args),
                }
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
            return {
                "status": "error",
                "issues": [text_issue("WPScan output could not be parsed", "Low", command_output(proc)[:500])],
                "summary": "WPScan returned invalid JSON output.",
                "command": shlex.join(args),
            }
        if not issues:
            failure = command_failure_result("WPScan", proc, args)
            if failure:
                return failure
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues[:50],
            "summary": f"WPScan returned {len(issues)} vulnerability indicator(s).",
            "command": shlex.join(args),
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
        if not issues:
            failure = command_failure_result("sqlmap", proc, args)
            if failure:
                return failure
        return {
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "summary": "sqlmap active validation completed.",
            "command": shlex.join(args),
        }


class NoSQLMapRunner:
    def __init__(self, binary: str | None, timeout: int, command_template: str | None = None):
        self.binary = binary
        self.timeout = timeout
        self.command_template = command_template

    def _query_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        return [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name]

    def _args_for(self, url: str, param: str | None) -> list[str]:
        if self.command_template:
            rendered = self.command_template.format(url=url, param=param or "", method="GET")
            return shlex.split(rendered)
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        uri = parsed.path or "/"
        if parsed.query:
            uri = f"{uri}?{parsed.query}"
        params = self._query_params(url)
        param_index = str(params.index(param) + 1) if param in params else "1"
        args = [
            self.binary or "nosqlmap",
            "--attack",
            "2",
            "--platform",
            "MongoDB",
            "--victim",
            parsed.hostname or parsed.netloc,
            "--webPort",
            str(port),
            "--uri",
            uri,
            "--httpMethod",
            "GET",
            "--https",
            "ON" if parsed.scheme == "https" else "OFF",
            "--verb",
            "OFF",
            "--injectSize",
            "8",
            "--injectFormat",
            "1",
            "--params",
            param_index,
            "--doTimeAttack",
            "n",
        ]
        if param:
            args.extend(["--injectedParameter", param_index])
        return args

    def scan(self, url: str, enabled: bool = False) -> dict[str, Any]:
        if not enabled:
            return disabled_result("NoSQLMap active validation")
        if self.command_template:
            probe_binary = shlex.split(self.command_template)[0] if self.command_template.strip() else None
            if not tool_available(probe_binary):
                return unavailable_result("NoSQLMap", probe_binary)
        elif not tool_available(self.binary):
            result = unavailable_result("NoSQLMap", self.binary)
            result["summary"] = "NoSQLMap was not found. Install/configure NoSQLMap to enable external NoSQL injection validation."
            return result

        params = self._query_params(url)
        if not params:
            return {
                "enabled": True,
                "status": "informational",
                "issues": [],
                "tested_parameters": [],
                "summary": "NoSQLMap was available, but no URL query parameters were present for this GET smoke test.",
                "recommendations": ["Use authenticated API capture or provide request templates to test JSON/body parameters for NoSQL injection."],
            }

        issues: list[dict[str, Any]] = []
        commands: list[str] = []
        summaries: list[str] = []
        for param in params[:5]:
            args = self._args_for(url, param)
            commands.append(shlex.join(args))
            try:
                proc = run_command(args, self.timeout)
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "issues": issues, "tested_parameters": params[:5], "summary": "NoSQLMap timed out.", "commands": commands}
            except Exception as exc:
                return {"status": "error", "issues": [text_issue("NoSQLMap failed", "Low", str(exc))], "tested_parameters": params[:5], "commands": commands}

            output = command_output(proc)
            summaries.append(output[:300])
            if proc.returncode != 0 and not output:
                failure = command_failure_result("NoSQLMap", proc, args, tested_parameters=params[:5])
                if failure:
                    return failure
            lower = output.lower()
            if any(marker in lower for marker in ["vulnerable", "injection found", "nosql injection", "exploitable"]):
                issues.append(text_issue("NoSQLMap reported possible NoSQL injection", "Critical", output[-1000:] or f"Parameter {param}", parameter=param, tool="NoSQLMap"))

        return {
            "enabled": True,
            "status": "issues_found" if issues else "ok",
            "issues": issues,
            "tested_parameters": params[:5],
            "summary": "NoSQLMap external validation completed." if not issues else f"NoSQLMap reported {len(issues)} possible issue(s).",
            "tool_output": "\n".join(part for part in summaries if part)[:1000],
            "commands": commands,
            "recommendations": ["Review NoSQLMap output and enforce strict schema validation for JSON/body/query parameters."] if issues else [],
        }


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
        bundled_wordlist = Path(__file__).resolve().parent.parent / "wordlists" / "ffuf-small.txt"
        wordlist = self.wordlist or str(bundled_wordlist)
        if not wordlist or not Path(wordlist).exists():
            return {
                "enabled": True,
                "status": "unavailable",
                "issues": [],
                "recommendations": ["Configure FFUF_WORDLIST with a small, approved discovery wordlist."],
                "summary": "ffuf wordlist is not configured.",
            }
        target = normalized_origin(url) + "/FUZZ"
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "ffuf.json"
            args = [self.binary or "ffuf", "-u", target, "-w", wordlist, "-of", "json", "-o", str(output_path), "-s", "-mc", "200,204,301,302,307,308,401,403"]
            try:
                proc = run_command(args, self.timeout)
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "issues": [], "summary": "ffuf timed out."}
            except Exception as exc:
                return {"status": "error", "issues": [text_issue("ffuf failed", "Low", str(exc))]}

            failure = command_failure_result("ffuf", proc, args, discovered=[])
            if failure:
                return failure

            results = []
            try:
                data = json.loads(output_path.read_text(errors="ignore") if output_path.exists() else "{}")
                results = data.get("results") or []
            except json.JSONDecodeError:
                return {
                    "status": "error",
                    "issues": [text_issue("ffuf output could not be parsed", "Low", command_output(proc)[:500])],
                    "discovered": [],
                    "summary": "ffuf returned invalid JSON output.",
                    "command": shlex.join(args),
                }
        issues = [
            text_issue("ffuf discovered reachable path", "Info", f"{item.get('url')} returned {item.get('status')}")
            for item in results[:50]
        ]
        return {
            "status": "informational" if issues else "ok",
            "issues": issues,
            "discovered": results[:50],
            "summary": f"ffuf discovered {len(results)} path(s).",
            "command": shlex.join(args),
        }
