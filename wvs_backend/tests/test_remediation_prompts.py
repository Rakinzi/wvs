from __future__ import annotations

from app.utils.remediation_prompts import build_builder_prompt


def test_accessibility_prompt_includes_element_and_evidence_context():
    prompt = build_builder_prompt(
        {
            "scanner": "accessibility",
            "title": "Form elements must have labels",
            "page_url": "https://example.com/",
            "selector": "#header-search",
            "evidence": {
                "description": '<input id="header-search" type="search"> is a visible form control with no associated label.',
                "element_summary": '<input id="header-search" type="search">',
            },
            "technical_remediation": 'Add a visible <label for="header-search">Search</label>.',
        }
    )

    assert '<input id="header-search" type="search">' in prompt
    assert "Evidence:" in prompt
    assert '<label for="header-search">Search</label>' in prompt
