from __future__ import annotations

from typing import Mapping


def build_builder_prompt(finding: Mapping[str, object]) -> str:
    page = str(finding.get("page_url") or "the affected page")
    title = str(finding.get("title") or "the identified issue")
    selector = str(finding.get("selector") or "").strip()
    selector_text = f" for `{selector}`" if selector else ""
    remediation = str(finding.get("technical_remediation") or "").strip()
    scanner = str(finding.get("scanner") or "")

    if scanner == "accessibility":
        return (
            f"Update {page} to fix the accessibility issue '{title}'{selector_text}. "
            f"{remediation or 'Use an accessible implementation that preserves the current layout and branding.'} "
            "Keep the current branding and ensure keyboard and screen-reader support."
        )
    if scanner == "responsive_ux":
        return (
            f"Fix the mobile/responsive issue '{title}' on {page}{selector_text}. "
            f"{remediation or 'Ensure the layout fits 390px screens without horizontal overflow or clipped controls.'} "
            "Preserve the current design and content hierarchy."
        )
    if scanner == "performance_ux":
        return (
            f"Improve the performance UX issue '{title}' on {page}. "
            f"{remediation or 'Reduce blocking work, optimize media, and preserve the current design.'} "
            "Do not remove existing branding or rewrite the full page."
        )
    if scanner == "form_usability":
        return (
            f"Improve the form usability issue '{title}' on {page}{selector_text}. "
            f"{remediation or 'Clarify labels, validation, and submit actions while keeping the current flow intact.'} "
            "Preserve existing branding and keep the change scoped to the affected form."
        )
    if scanner == "seo":
        return (
            f"Fix the SEO readiness issue '{title}' on {page}{selector_text}. "
            f"{remediation or 'Update metadata, headings, or crawl configuration while preserving page content and behavior.'} "
            "Keep the change scoped to SEO metadata or semantic structure unless the finding requires visible copy."
        )
    if scanner == "broken_links":
        return (
            f"Fix the broken link issue '{title}' on {page}{selector_text}. "
            f"{remediation or 'Update the target URL, restore the missing route, or remove the link while preserving the current page layout.'} "
            "Check both desktop and mobile navigation after the change."
        )
    if scanner == "app_controls":
        return (
            f"Fix the pre-production application-control issue '{title}' on {page}{selector_text}. "
            f"{remediation or 'Add server-side controls and keep the change scoped to the affected route or workflow.'} "
            "Preserve existing UX while enforcing the control on the backend."
        )
    if scanner == "exposed_services":
        return (
            f"Fix the exposed-service issue '{title}' for {page}. "
            f"{remediation or 'Close the public port or restrict it with firewall/private-network controls before launch.'} "
            "Verify from an external network that only intended public web services remain reachable."
        )
    if scanner == "visual_ai":
        return (
            f"Improve the visual/product-quality recommendation '{title}' on {page}. "
            f"{remediation or 'Refine hierarchy, spacing, and CTA clarity while preserving the current brand style.'}"
        )
    if scanner == "ssrf":
        return (
            f"Fix the SSRF vulnerability '{title}' on {page}{selector_text}. "
            f"{remediation or 'Validate and allowlist all server-side URL destinations. Block requests to RFC-1918 ranges, loopback addresses, and cloud metadata services (169.254.169.254).'} "
            "Apply the fix server-side; do not rely on client-side filtering."
        )
    if scanner == "logging_monitor":
        return (
            f"Fix the logging/monitoring gap '{title}' on {page}. "
            f"{remediation or 'Add error monitoring, structured logging, and security event alerting before launch.'} "
            "Keep the change scoped to infrastructure configuration and monitoring SDK integration."
        )
    if scanner == "auth":
        return (
            f"Fix the authentication issue '{title}' on {page}{selector_text}. "
            f"{remediation or 'Apply the fix server-side with the smallest change that resolves the issue without breaking existing auth flows.'} "
            "Test login, logout, and session expiry after the change."
        )
    if scanner == "integrity":
        return (
            f"Fix the software integrity issue '{title}' on {page}{selector_text}. "
            f"{remediation or 'Add integrity hashes (SRI) to external scripts/stylesheets and implement a Content-Security-Policy header.'} "
            "Verify the fix does not break third-party integrations."
        )

    return (
        f"Fix the issue '{title}' on {page}{selector_text}. "
        f"{remediation or 'Apply the smallest safe change that resolves the issue while preserving branding and behavior.'}"
    )
