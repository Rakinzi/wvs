from __future__ import annotations

import hashlib
from typing import Any, Mapping


SECURITY_SCANNERS = {
    "sqli",
    "ssl",
    "headers",
    "wordpress",
    "zap",
    "malicious",
    "xss",
    "tech",
    "exposure",
    "secrets",
    "dns",
    "redirect",
    "takeover",
    "malware_analysis",
    "ssrf",
    "logging_monitor",
    "auth",
    "integrity",
}

UX_SCANNERS = {"accessibility", "responsive_ux", "performance_ux", "form_usability", "broken_links", "app_controls", "exposed_services"}

SCANNER_CATEGORY = {
    "sqli": ("Security", "Input Validation"),
    "ssl": ("Security", "Transport Security"),
    "headers": ("Security", "Security Headers"),
    "wordpress": ("Security", "WordPress"),
    "zap": ("Security", "DAST"),
    "malicious": ("Security", "Reputation"),
    "xss": ("Security", "Cross-Site Scripting"),
    "tech": ("Security", "Technology Risk"),
    "exposure": ("Security", "Sensitive Exposure"),
    "secrets": ("Security", "Public Secret Exposure"),
    "dns": ("Security", "DNS Hygiene"),
    "redirect": ("Security", "Open Redirect"),
    "takeover": ("Security", "Subdomain Takeover"),
    "malware_analysis": ("Security", "Malware Exposure"),
    "ssrf": ("Security", "Server-Side Request Forgery"),
    "logging_monitor": ("Security", "Logging & Monitoring"),
    "auth": ("Security", "Authentication"),
    "integrity": ("Security", "Software Integrity"),
    "accessibility": ("Accessibility", "WCAG Readiness"),
    "responsive_ux": ("Product UX", "Mobile Layout"),
    "performance_ux": ("Performance UX", "Core Web Vitals"),
    "form_usability": ("Product UX", "Form Usability"),
    "seo": ("SEO Readiness", "Search Foundations"),
    "broken_links": ("Product UX", "Broken Links"),
    "app_controls": ("Application Controls", "Pre-production Controls"),
    "exposed_services": ("Network Exposure", "Exposed Services"),
    "visual_ai": ("Visual UX", "AI Visual Review"),
}

STANDARD_REFERENCE = {
    "sqli": "OWASP ASVS / OWASP WSTG",
    "ssl": "OWASP ASVS - Communications Security",
    "headers": "OWASP ASVS - HTTP Security Headers",
    "wordpress": "OWASP WSTG - Fingerprinting and Configuration",
    "zap": "OWASP WSTG",
    "malicious": "Threat reputation heuristics",
    "xss": "OWASP ASVS / OWASP WSTG - Cross-Site Scripting",
    "tech": "OWASP WSTG - Fingerprinting and Components",
    "exposure": "OWASP ASVS - Sensitive Data and Configuration",
    "secrets": "Public exposed secret heuristics",
    "dns": "DNS security and deliverability checks",
    "redirect": "OWASP WSTG - Client-Side Redirects",
    "takeover": "Subdomain takeover fingerprinting",
    "malware_analysis": "Public artifact malware heuristics",
    "ssrf": "OWASP WSTG - SSRF (OTG-INPVAL-019)",
    "logging_monitor": "OWASP WSTG - Testing for Insufficient Logging",
    "auth": "OWASP ASVS - Authentication",
    "integrity": "OWASP ASVS - Software Integrity",
    "accessibility": "WCAG 2.2 AA",
    "responsive_ux": "Measured browser layout checks",
    "performance_ux": "Core Web Vitals / browser performance measurements",
    "form_usability": "Measured form usability heuristics",
    "seo": "Google Search Essentials / Search Central guidance",
    "broken_links": "Rendered link availability checks",
    "app_controls": "Pre-production auth/API control checks",
    "exposed_services": "Bounded TCP exposed-service checks",
    "visual_ai": "AI-assisted advisory review",
}

SCANNER_OWASP_MAP: dict[str, str] = {
    "sqli":             "A03:2021 – Injection",
    "xss":              "A03:2021 – Injection",
    "zap":              "A03:2021 – Injection",
    "ssl":              "A02:2021 – Cryptographic Failures",
    "headers":          "A05:2021 – Security Misconfiguration",
    "wordpress":        "A05:2021 – Security Misconfiguration",
    "exposure":         "A05:2021 – Security Misconfiguration",
    "secrets":          "A02:2021 – Cryptographic Failures",
    "malicious":        "A04:2021 – Insecure Design",
    "malware_analysis": "A06:2021 – Vulnerable and Outdated Components",
    "tech":             "A06:2021 – Vulnerable and Outdated Components",
    "dns":              "A05:2021 – Security Misconfiguration",
    "redirect":         "A01:2021 – Broken Access Control",
    "takeover":         "A01:2021 – Broken Access Control",
    "app_controls":     "A01:2021 – Broken Access Control",
    "exposed_services": "A05:2021 – Security Misconfiguration",
    "abuse_controls":   "A04:2021 – Insecure Design",
    "ssrf":             "A10:2021 – Server-Side Request Forgery",
    "logging_monitor":  "A09:2021 – Security Logging and Monitoring Failures",
    "auth":             "A07:2021 – Identification and Authentication Failures",
    "integrity":        "A08:2021 – Software and Data Integrity Failures",
}


def _stable_id(parts: list[Any]) -> str:
    fingerprint = "|".join(str(part or "") for part in parts)
    return hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:16]


def _severity(value: Any) -> str:
    normalized = str(value or "informational").strip().lower()
    if normalized in {"critical", "high", "medium", "low", "recommendation", "informational"}:
        return normalized
    if normalized in {"info", "notice"}:
        return "informational"
    return "informational"


def _confidence(scanner: str, issue: Mapping[str, Any]) -> str:
    raw = str(issue.get("confidence") or "").strip().lower()
    if raw in {"high", "medium", "low", "measured", "heuristic", "ai_assisted"}:
        return {"measured": "high", "heuristic": "medium", "ai_assisted": "medium"}.get(raw, raw)
    if scanner in SECURITY_SCANNERS:
        return "high"
    if scanner in UX_SCANNERS or scanner == "seo":
        return "high"
    if scanner == "visual_ai":
        return "medium"
    return "medium"


def _evidence_type(scanner: str, issue: Mapping[str, Any]) -> str:
    raw = str(issue.get("evidence_type") or "").strip().lower()
    if raw:
        return raw
    if scanner in SECURITY_SCANNERS:
        return "confirmed_technical_issue"
    if scanner in UX_SCANNERS:
        return "measured_ux_failure"
    if scanner == "seo":
        return "heuristic_ux_risk"
    if scanner == "visual_ai":
        return "ai_visual_recommendation"
    return "heuristic_ux_risk"


def _launch_impact(scanner: str, severity: str, evidence_type: str) -> str:
    if evidence_type == "ai_visual_recommendation":
        return "recommendation"

    if scanner in SECURITY_SCANNERS:
        if severity == "critical":
            return "blocked"
        if severity == "high" and scanner in {
            "sqli",
            "xss",
            "exposure",
            "secrets",
            "malicious",
            "redirect",
            "takeover",
            "malware_analysis",
            "ssrf",
            "auth",
        }:
            return "blocked"
        if severity in {"high", "medium"}:
            return "fix_before_ship"
        return "recommendation"

    if scanner in {"accessibility", "responsive_ux", "form_usability"} and severity in {"critical", "high"}:
        return "blocked"
    if scanner == "performance_ux" and severity in {"critical", "high"}:
        return "fix_before_ship"
    if scanner == "seo" and severity == "high":
        return "fix_before_ship"
    if severity == "medium":
        return "fix_before_ship"
    if severity == "low":
        return "monitor_after_ship"
    return "recommendation"


def _issue_title(scanner: str, issue: Mapping[str, Any]) -> str:
    return str(
        issue.get("title")
        or issue.get("name")
        or issue.get("type")
        or issue.get("summary")
        or f"{scanner.replace('_', ' ').title()} finding"
    )


def _evidence_payload(issue: Mapping[str, Any]) -> dict[str, Any]:
    evidence = issue.get("evidence")
    if isinstance(evidence, Mapping):
        return dict(evidence)
    return {
        "description": str(evidence or issue.get("reason") or issue.get("details") or ""),
        "raw_data_redacted": True,
    }


def normalize_launch_finding(scanner: str, issue: Mapping[str, Any]) -> dict[str, Any]:
    category, sub_category = SCANNER_CATEGORY.get(scanner, (scanner.replace("_", " ").title(), "General"))
    severity = _severity(issue.get("severity") or issue.get("risk"))
    evidence_type = _evidence_type(scanner, issue)
    title = _issue_title(scanner, issue)
    affected_url = str(issue.get("page_url") or issue.get("url") or issue.get("affected_url") or "")
    viewport = issue.get("viewport")
    selector = issue.get("selector") or issue.get("parameter")
    confidence = _confidence(scanner, issue)
    launch_impact = _launch_impact(scanner, severity, evidence_type)

    finding = {
        "finding_id": str(issue.get("finding_id") or issue.get("id") or _stable_id([scanner, title, affected_url, viewport, selector])),
        "scanner": scanner,
        "category": category,
        "sub_category": sub_category,
        "title": title,
        "severity": severity,
        "evidence_type": evidence_type,
        "launch_impact": launch_impact,
        "confidence": confidence,
        "affected_url": affected_url,
        "viewport": viewport,
        "selector": selector,
        "standard_reference": str(issue.get("standard_reference") or STANDARD_REFERENCE.get(scanner, "")),
        "owasp_category": str(issue.get("owasp_category") or SCANNER_OWASP_MAP.get(scanner, "")),
        "evidence": _evidence_payload(issue),
        "why_it_matters": str(issue.get("user_impact") or issue.get("why_it_matters") or ""),
        "recommended_fix": str(issue.get("technical_remediation") or issue.get("recommended_fix") or ""),
        "builder_prompt": str(issue.get("builder_prompt") or ""),
        "status": str(issue.get("status") or "open"),
    }
    return finding


def _synthetic_issues(scanner: str, payload: Any) -> list[dict[str, Any]]:
    if scanner == "ssl" and isinstance(payload, Mapping) and payload.get("valid") is False:
        return [{
            "title": "SSL/TLS certificate issue",
            "severity": "high",
            "evidence": payload.get("error") or "Certificate validation failed.",
            "technical_remediation": "Fix certificate validity, hostname coverage, and trust-chain issues before launch.",
            "user_impact": "Users may see browser security warnings or lose trust before using the app.",
        }]
    if scanner == "malicious" and isinstance(payload, Mapping) and payload.get("is_malicious"):
        return [{
            "title": "Target flagged as potentially malicious",
            "severity": "critical" if (payload.get("score") or 0) >= 8 else "high",
            "evidence": payload.get("reason") or "Threat reputation checks flagged the target.",
            "technical_remediation": "Investigate compromise, injected content, and reputation list causes before launch.",
            "user_impact": "Users and browsers may block or distrust the site.",
        }]
    return []


def extract_universal_findings(findings: Mapping[str, Any]) -> list[dict[str, Any]]:
    scanner_keys = [
        "sqli",
        "ssl",
        "headers",
        "wordpress",
        "zap",
        "malicious",
        "xss",
        "tech",
        "exposure",
        "secrets",
        "dns",
        "redirect",
        "takeover",
        "malware_analysis",
        "ssrf",
        "logging_monitor",
        "auth",
        "integrity",
        "accessibility",
        "responsive_ux",
        "performance_ux",
        "form_usability",
        "seo",
        "visual_ai",
    ]
    normalized: list[dict[str, Any]] = []
    for scanner in scanner_keys:
        payload = findings.get(scanner)
        if scanner == "sqli" and isinstance(payload, list):
            issues = payload
        elif isinstance(payload, Mapping):
            issues = list(payload.get("issues") or [])
            issues.extend(_synthetic_issues(scanner, payload))
        else:
            issues = []

        for issue in issues:
            if isinstance(issue, Mapping):
                normalized.append(normalize_launch_finding(scanner, issue))
    return normalized
