from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse

from app.settings import settings
from app.utils.finding_normalizer import to_report_finding


def _resolve_target_ips(hostname: str, port: int | None) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    resolved_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    target_port = port or 443

    try:
        records = socket.getaddrinfo(hostname, target_port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Could not resolve target hostname") from exc

    for record in records:
        sockaddr = record[4]
        ip_value = sockaddr[0]
        resolved_ips.add(ipaddress.ip_address(ip_value))

    if not resolved_ips:
        raise ValueError("Could not resolve target hostname")

    return resolved_ips


def _validate_target_host(parsed_url) -> None:
    hostname = parsed_url.hostname
    if not hostname:
        raise ValueError("Invalid URL")

    if parsed_url.username or parsed_url.password:
        raise ValueError("URLs with embedded credentials are not allowed")

    if hostname.lower() == "localhost" or hostname.lower().endswith(".local"):
        raise ValueError("Local network targets are not allowed")

    if settings.allow_private_scan_targets:
        return

    for resolved_ip in _resolve_target_ips(hostname, parsed_url.port):
        if not resolved_ip.is_global:
            raise ValueError("Private or reserved network targets are not allowed")


def normalize_target_url(raw_url: str | None) -> str:
    if not raw_url:
        raise ValueError("URL is required")

    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("URL is required")

    if not candidate.startswith(("http://", "https://")):
        raise ValueError("Invalid URL protocol")

    parsed = urlparse(candidate)
    if not parsed.netloc:
        raise ValueError("Invalid URL")

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Invalid URL protocol")

    _validate_target_host(parsed)

    return parsed.geturl()


def extract_target_origin(raw_url: str | None) -> str:
    normalized = normalize_target_url(raw_url)
    parsed = urlparse(normalized)
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_target_hostname(raw_url: str | None) -> str:
    normalized = normalize_target_url(raw_url)
    parsed = urlparse(normalized)
    if not parsed.hostname:
        raise ValueError("Invalid URL")
    return parsed.hostname.lower()


def validate_target_redirect(url: str, expected_hostname: str) -> str:
    normalized = normalize_target_url(url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    if hostname != expected_hostname.lower():
        raise ValueError("Redirect target hostname is not allowed")
    return normalized


def build_scan_summary(findings: dict[str, Any]) -> dict[str, Any]:
    sqli_findings = findings.get("sqli", []) or []
    ssl_findings = findings.get("ssl", {}) or {}
    malicious_findings = findings.get("malicious", {}) or {}
    header_findings = findings.get("headers", {}) or {}
    wordpress_findings = findings.get("wordpress", {}) or {}
    zap_findings = findings.get("zap", {}) or {}
    xss_findings = findings.get("xss", {}) or {}
    tech_findings = findings.get("tech", {}) or {}
    exposure_findings = findings.get("exposure", {}) or {}
    dns_findings = findings.get("dns", {}) or {}
    redirect_findings = findings.get("redirect", {}) or {}
    takeover_findings = findings.get("takeover", {}) or {}
    accessibility_findings = findings.get("accessibility", {}) or {}
    responsive_findings = findings.get("responsive_ux", {}) or {}
    performance_findings = findings.get("performance_ux", {}) or {}
    form_findings = findings.get("form_usability", {}) or {}
    visual_findings = findings.get("visual_ai", {}) or {}
    header_issues = header_findings.get("issues", []) or []
    wordpress_issues = wordpress_findings.get("issues", []) or []
    zap_issues = zap_findings.get("issues", []) or []
    xss_issues = xss_findings.get("issues", []) or []
    tech_issues = tech_findings.get("issues", []) or []
    actionable_tech_issues = [i for i in tech_issues if str(i.get("severity", "Info")).title() != "Info"]
    tech_packages = tech_findings.get("packages", []) or []
    tech_advisories = tech_findings.get("advisories", []) or []
    exposure_issues = exposure_findings.get("issues", []) or []
    dns_issues = dns_findings.get("issues", []) or []
    redirect_issues = redirect_findings.get("issues", []) or []
    takeover_issues = takeover_findings.get("issues", []) or []
    accessibility_issues = accessibility_findings.get("issues", []) or []
    responsive_issues = responsive_findings.get("issues", []) or []
    performance_issues = performance_findings.get("issues", []) or []
    form_issues = form_findings.get("issues", []) or []
    visual_issues = visual_findings.get("issues", []) or []
    launch_blockers = [
        issue
        for issue in accessibility_issues + responsive_issues + performance_issues + form_issues
        if str(issue.get("severity") or "").lower() in {"critical", "high"}
    ]

    vulnerable = (
        bool(sqli_findings)
        or ssl_findings.get("valid") is False
        or malicious_findings.get("is_malicious", False)
        or bool(header_issues)
        or bool(wordpress_issues)
        or bool(zap_issues)
        or bool([i for i in xss_issues if i.get("severity") in ("High", "Critical")])
        or bool(actionable_tech_issues)
        or bool(tech_advisories)
        or bool([i for i in exposure_issues if i.get("severity") in ("Critical", "High")])
        or bool([i for i in dns_issues if i.get("severity") in ("High", "Critical")])
        or bool(redirect_issues)
        or bool(takeover_issues)
        or bool(launch_blockers)
    )

    total_issues = (
        len(sqli_findings) + len(header_issues) + len(wordpress_issues) +
        len(zap_issues) + len(xss_issues) + len(actionable_tech_issues) + len(tech_advisories) +
        len(exposure_issues) + len(dns_issues) + len(redirect_issues) + len(takeover_issues) +
        len(accessibility_issues) + len(responsive_issues) + len(performance_issues) + len(form_issues)
    )
    if ssl_findings.get("valid") is False:
        total_issues += 1
    if malicious_findings.get("is_malicious", False):
        total_issues += 1

    security_score = 100 if total_issues == 0 else max(0, 100 - (total_issues * 20))

    return {
        "vulnerable": vulnerable,
        "total_issues": total_issues,
        "score": security_score,
        "security_score": security_score,
        "sqli_count": len(sqli_findings),
        "ssl_issue": ssl_findings.get("valid") is False,
        "malicious": malicious_findings.get("is_malicious", False),
        "header_issue_count": len(header_issues),
        "wordpress_issue_count": len(wordpress_issues),
        "zap_issue_count": len(zap_issues),
        "xss_count": len([i for i in xss_issues if i.get("type") == "Reflected XSS"]),
        "tech_issue_count": len(actionable_tech_issues),
        "package_count": len(tech_packages),
        "advisory_count": len(tech_advisories),
        "exposure_count": len(exposure_issues),
        "dns_issue_count": len(dns_issues),
        "redirect_count": len(redirect_issues),
        "takeover_count": len(takeover_issues),
        "accessibility_issue_count": len(accessibility_issues),
        "responsive_issue_count": len(responsive_issues),
        "performance_issue_count": len(performance_issues),
        "form_issue_count": len(form_issues),
        "visual_ai_issue_count": len(visual_issues),
        "launch_blocker_count": len(launch_blockers),
        "accessibility_score": accessibility_findings.get("score"),
        "responsive_score": responsive_findings.get("score"),
        "performance_score": performance_findings.get("score"),
        "usability_score": form_findings.get("score"),
        "launch_readiness_score": findings.get("launch_readiness", {}).get("score"),
    }


def _severity_counts(issues: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for issue in issues:
        severity = str(issue.get("severity") or issue.get("risk") or "Info").title()
        if severity not in counts:
            severity = "Info"
        counts[severity] += 1
    return counts


def build_scan_sections(findings: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sqli_findings = findings.get("sqli", []) or []
    ssl_findings = findings.get("ssl", {}) or {}
    malicious_findings = findings.get("malicious", {}) or {}
    header_findings = findings.get("headers", {}) or {}
    wordpress_findings = findings.get("wordpress", {}) or {}
    zap_findings = findings.get("zap", {}) or {}
    tech_findings = findings.get("tech", {}) or {}

    ssl_issues = []
    if ssl_findings.get("valid") is False:
        ssl_issues.append(
            {
                "name": "SSL/TLS certificate issue",
                "severity": "High" if not ssl_findings.get("self_signed") else "Medium",
                "evidence": ssl_findings.get("error", "Certificate validation failed"),
            }
        )

    malicious_issues = []
    if malicious_findings.get("is_malicious", False):
        evidence_parts = [f"Threat score: {malicious_findings.get('score', 0)}/10"]
        if malicious_findings.get("phishing_match"):
            evidence_parts.append("Known phishing pattern match")
        if malicious_findings.get("dnsbl", {}).get("blacklisted"):
            evidence_parts.append(
                f"DNSBL hits: {malicious_findings.get('dnsbl', {}).get('total_detected', 0)}"
            )
        malicious_issues.append(
            {
                "name": "Potentially malicious target",
                "severity": "Critical" if malicious_findings.get("score", 0) >= 8 else "High",
                "evidence": " | ".join(evidence_parts),
            }
        )

    xss_findings = findings.get("xss", {}) or {}
    exposure_findings = findings.get("exposure", {}) or {}
    dns_findings = findings.get("dns", {}) or {}
    redirect_findings = findings.get("redirect", {}) or {}
    takeover_findings = findings.get("takeover", {}) or {}
    accessibility_findings = findings.get("accessibility", {}) or {}
    responsive_findings = findings.get("responsive_ux", {}) or {}
    performance_findings = findings.get("performance_ux", {}) or {}
    form_findings = findings.get("form_usability", {}) or {}
    visual_findings = findings.get("visual_ai", {}) or {}

    sections = {
        "sql": {
            "label": "SQL Injection Analysis",
            "status": "issues_found" if sqli_findings else "ok",
            "issue_count": len(sqli_findings),
            "severity_counts": _severity_counts(sqli_findings),
            "top_findings": sqli_findings[:5],
            "recommendations": [
                "Use parameterized queries or prepared statements",
                "Implement proper input validation and sanitization",
                "Apply the principle of least privilege for database users",
            ] if sqli_findings else [],
        },
        "ssl": {
            "label": "SSL/TLS Certificate Analysis",
            "status": "issues_found" if ssl_issues else "ok",
            "issue_count": len(ssl_issues),
            "severity_counts": _severity_counts(ssl_issues),
            "top_findings": ssl_issues,
            "recommendations": [
                "Obtain a valid SSL/TLS certificate from a trusted certificate authority",
                "Use strong cipher suites and modern protocols (TLS 1.2 or higher)",
                "Implement HTTP Strict Transport Security (HSTS)",
            ] if ssl_issues else [],
        },
        "headers": {
            "label": "HTTP Header Security",
            "status": header_findings.get("status", "not_run"),
            "issue_count": len(header_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(header_findings.get("issues", []) or []),
            "top_findings": (header_findings.get("issues", []) or [])[:5],
            "recommendations": header_findings.get("recommendations", []) or [],
        },
        "wordpress": {
            "label": "WordPress Security Analysis",
            "status": wordpress_findings.get("status", "not_run"),
            "issue_count": len(wordpress_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(wordpress_findings.get("issues", []) or []),
            "top_findings": (wordpress_findings.get("issues", []) or [])[:5],
            "recommendations": wordpress_findings.get("recommendations", []) or [],
        },
        "zap": {
            "label": "OWASP ZAP Analysis",
            "status": zap_findings.get("status", "not_run"),
            "issue_count": len(zap_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(zap_findings.get("issues", []) or []),
            "top_findings": (zap_findings.get("issues", []) or [])[:5],
            "recommendations": zap_findings.get("recommendations", []) or [],
        },
        "xss": {
            "label": "Cross-Site Scripting (XSS)",
            "status": xss_findings.get("status", "not_run"),
            "issue_count": len(xss_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(xss_findings.get("issues", []) or []),
            "top_findings": (xss_findings.get("issues", []) or [])[:5],
            "recommendations": xss_findings.get("recommendations", []) or [
                "Encode all user-supplied output using context-aware encoding.",
                "Implement a strict Content-Security-Policy header.",
                "Use HttpOnly and Secure flags on session cookies.",
            ] if (xss_findings.get("issues") or []) else [],
        },
        "tech": {
            "label": "Technology Fingerprinting",
            "status": tech_findings.get("status", "not_run"),
            "issue_count": len(tech_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(tech_findings.get("issues", []) or []),
            "top_findings": (tech_findings.get("issues", []) or [])[:5],
            "recommendations": tech_findings.get("recommendations", []) or [],
        },
        "exposure": {
            "label": "Sensitive File Exposure",
            "status": exposure_findings.get("status", "not_run"),
            "issue_count": len(exposure_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(exposure_findings.get("issues", []) or []),
            "top_findings": (exposure_findings.get("issues", []) or [])[:5],
            "recommendations": exposure_findings.get("recommendations", []) or [],
        },
        "malicious": {
            "label": "Malicious Content Analysis",
            "status": "issues_found" if malicious_issues else "ok",
            "issue_count": len(malicious_issues),
            "severity_counts": _severity_counts(malicious_issues),
            "top_findings": malicious_issues,
            "recommendations": [
                "Avoid sharing sensitive information on this website",
                "Block access to this domain in your organization",
                "If this is your website, investigate potential compromise",
            ] if malicious_issues else [],
        },
        "dns": {
            "label": "DNS Security (SPF / DMARC / DKIM)",
            "status": dns_findings.get("status", "not_run"),
            "issue_count": len(dns_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(dns_findings.get("issues", []) or []),
            "top_findings": (dns_findings.get("issues", []) or [])[:5],
            "recommendations": dns_findings.get("recommendations", []) or [],
        },
        "redirect": {
            "label": "Open Redirect",
            "status": redirect_findings.get("status", "not_run"),
            "issue_count": len(redirect_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(redirect_findings.get("issues", []) or []),
            "top_findings": (redirect_findings.get("issues", []) or [])[:5],
            "recommendations": redirect_findings.get("recommendations", []) or [],
        },
        "takeover": {
            "label": "Subdomain Takeover",
            "status": takeover_findings.get("status", "not_run"),
            "issue_count": len(takeover_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(takeover_findings.get("issues", []) or []),
            "top_findings": (takeover_findings.get("issues", []) or [])[:5],
            "recommendations": takeover_findings.get("recommendations", []) or [],
        },
        "accessibility": {
            "label": "Accessibility",
            "status": accessibility_findings.get("status", "not_run"),
            "issue_count": len(accessibility_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(accessibility_findings.get("issues", []) or []),
            "top_findings": [to_report_finding(item) for item in (accessibility_findings.get("issues", []) or [])[:5]],
            "recommendations": accessibility_findings.get("recommendations", []) or [],
        },
        "responsive_ux": {
            "label": "Mobile and Responsive UX",
            "status": responsive_findings.get("status", "not_run"),
            "issue_count": len(responsive_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(responsive_findings.get("issues", []) or []),
            "top_findings": [to_report_finding(item) for item in (responsive_findings.get("issues", []) or [])[:5]],
            "recommendations": responsive_findings.get("recommendations", []) or [],
        },
        "performance_ux": {
            "label": "Performance UX",
            "status": performance_findings.get("status", "not_run"),
            "issue_count": len(performance_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(performance_findings.get("issues", []) or []),
            "top_findings": [to_report_finding(item) for item in (performance_findings.get("issues", []) or [])[:5]],
            "recommendations": performance_findings.get("recommendations", []) or [],
        },
        "form_usability": {
            "label": "Form and Interaction Usability",
            "status": form_findings.get("status", "not_run"),
            "issue_count": len(form_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(form_findings.get("issues", []) or []),
            "top_findings": [to_report_finding(item) for item in (form_findings.get("issues", []) or [])[:5]],
            "recommendations": form_findings.get("recommendations", []) or [],
        },
        "visual_ai": {
            "label": "Visual UX Recommendations",
            "status": visual_findings.get("status", "not_run"),
            "issue_count": len(visual_findings.get("issues", []) or []),
            "severity_counts": _severity_counts(visual_findings.get("issues", []) or []),
            "top_findings": [to_report_finding(item) for item in (visual_findings.get("issues", []) or [])[:5]],
            "recommendations": visual_findings.get("recommendations", []) or [],
        },
    }

    return sections


def build_best_practices(findings: dict[str, Any]) -> list[str]:
    tech_findings = findings.get("tech", {}) or {}
    malicious_findings = findings.get("malicious", {}) or {}
    xss_findings = findings.get("xss", {}) or {}
    header_findings = findings.get("headers", {}) or {}
    exposure_findings = findings.get("exposure", {}) or {}

    practices: list[str] = []

    if tech_findings.get("packages"):
        practices.extend([
            "Maintain an SBOM for frontend and backend dependencies, and update it on every release.",
            "Run dependency scanning in CI/CD and block deployments for critical or high-severity advisories.",
            "Pin package versions with lockfiles and review third-party CDN usage with Subresource Integrity (SRI).",
        ])

    if tech_findings.get("advisories"):
        practices.extend([
            "Patch vulnerable packages promptly and document accepted risk when remediation cannot be immediate.",
            "Track CVE and CWE exposure as part of release readiness for internal and client-facing applications.",
        ])

    if (xss_findings.get("issues") or []) or not xss_findings.get("csp_present", True):
        practices.append("Adopt secure-by-default output encoding and enforce a strict Content-Security-Policy across all templates and SPAs.")

    if (header_findings.get("issues") or []):
        practices.append("Standardize security headers and cookie flags in a shared middleware layer so new vibecoded pages inherit safe defaults.")

    if (exposure_findings.get("issues") or []):
        practices.append("Keep source, backup, env, and debug artifacts out of the web root, and validate deployment bundles before publish.")
    if (findings.get("accessibility", {}) or {}).get("issues"):
        practices.append("Run mobile accessibility checks on every release candidate and treat missing labels and inaccessible controls as launch blockers.")
    if (findings.get("responsive_ux", {}) or {}).get("issues"):
        practices.append("Review primary pages on narrow mobile viewports before release and block launches with horizontal overflow or clipped forms.")
    if (findings.get("performance_ux", {}) or {}).get("issues"):
        practices.append("Track mobile performance budgets for key landing and signup pages so regressions are caught before launch.")

    if malicious_findings.get("is_malicious"):
        practices.append("Separate reputation signals from blocking decisions and require corroborating evidence before auto-blocking production traffic.")

    practices.extend([
        "Use authenticated code review and protected branches even for AI-generated code; fast generation increases the need for release guardrails.",
        "Add pre-production checks for secrets, dependency risk, headers, and exposed debug routes before every deployment.",
    ])

    seen: set[str] = set()
    return [item for item in practices if not (item in seen or seen.add(item))]


def build_risk_rating(summary: dict[str, Any]) -> str:
    total_issues = summary.get("total_issues", 0)
    is_malicious = summary.get("malicious", False)

    if total_issues > 5 or is_malicious:
        return "Critical"
    if total_issues > 3:
        return "High"
    if total_issues > 0:
        return "Medium"
    return "Low"


def build_security_score(summary: dict[str, Any]) -> int:
    total_issues = summary.get("total_issues", 0)
    return 100 if total_issues == 0 else max(0, 100 - (total_issues * 20))


def build_report_meta(scan_id: int, url: str, timestamp: str, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "target_url": url,
        "timestamp": timestamp,
        "risk_rating": build_risk_rating(summary),
        "security_score": build_security_score(summary),
        "accessibility_score": summary.get("accessibility_score"),
        "responsive_score": summary.get("responsive_score"),
        "performance_score": summary.get("performance_score"),
        "usability_score": summary.get("usability_score"),
        "launch_readiness_score": summary.get("launch_readiness_score"),
    }
