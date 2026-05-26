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
    if scanner == "visual_ai":
        return (
            f"Improve the visual/product-quality recommendation '{title}' on {page}. "
            f"{remediation or 'Refine hierarchy, spacing, and CTA clarity while preserving the current brand style.'}"
        )

    return (
        f"Fix the issue '{title}' on {page}{selector_text}. "
        f"{remediation or 'Apply the smallest safe change that resolves the issue while preserving branding and behavior.'}"
    )
