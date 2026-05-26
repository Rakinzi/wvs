from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from app.settings import settings
from app.utils.finding_normalizer import normalize_ux_findings


@dataclass
class VisualAIProvider:
    enabled: bool = False

    def is_available(self) -> bool:
        return self.enabled

    def analyse_page_screenshot(
        self,
        image_path: str,
        page_url: str,
        viewport: str,
        page_type: str | None = None,
    ) -> list[dict[str, Any]]:
        return []


class NoOpVisualAIProvider(VisualAIProvider):
    def __init__(self) -> None:
        super().__init__(enabled=False)


class OpenAICompatibleVisualAIProvider(VisualAIProvider):
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str,
        timeout_seconds: int = 45,
    ) -> None:
        super().__init__(enabled=bool(api_key and model))
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _build_prompt(self, page_url: str, viewport: str, page_type: str | None) -> str:
        page_hint = f"Page type: {page_type}." if page_type else "Page type is unknown."
        return (
            "Review this website screenshot and return only structured UX/product-quality recommendations. "
            "Do not claim confirmed security defects, confirmed accessibility violations, or guaranteed conversion outcomes. "
            "Focus on visual hierarchy, CTA prominence, trust signals, clutter, spacing consistency, mobile clarity, "
            "and product-readiness concerns.\n"
            f"Target URL: {page_url}\n"
            f"Viewport: {viewport}\n"
            f"{page_hint}\n"
            "Return JSON with a top-level 'findings' array. Each finding must include: "
            "category, title, severity, confidence, observation, user_impact, technical_remediation, builder_prompt."
        )

    def _load_image_data_url(self, image_path: str) -> str:
        raw = Path(image_path).read_bytes()
        encoded = base64.b64encode(raw).decode("ascii")
        return f"data:image/png;base64,{encoded}"

    def _extract_json_payload(self, response_json: dict[str, Any]) -> dict[str, Any]:
        choices = response_json.get("choices") or []
        if not choices:
            return {"findings": []}
        message = (choices[0] or {}).get("message") or {}
        content = message.get("content")
        if isinstance(content, str):
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"findings": []}
        if isinstance(content, list):
            text_chunks: list[str] = []
            for chunk in content:
                if isinstance(chunk, dict) and chunk.get("type") == "text":
                    text_chunks.append(str(chunk.get("text") or ""))
            try:
                return json.loads("".join(text_chunks))
            except json.JSONDecodeError:
                return {"findings": []}
        return {"findings": []}

    def analyse_page_screenshot(
        self,
        image_path: str,
        page_url: str,
        viewport: str,
        page_type: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self.is_available():
            return []

        payload = {
            "model": self.model,
            "temperature": 0.2,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "visual_ux_findings",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "findings": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "category": {"type": "string"},
                                        "title": {"type": "string"},
                                        "severity": {"type": "string"},
                                        "confidence": {"type": "string"},
                                        "observation": {"type": "string"},
                                        "user_impact": {"type": "string"},
                                        "technical_remediation": {"type": "string"},
                                        "builder_prompt": {"type": "string"},
                                    },
                                    "required": [
                                        "category",
                                        "title",
                                        "severity",
                                        "confidence",
                                        "observation",
                                        "user_impact",
                                        "technical_remediation",
                                        "builder_prompt",
                                    ],
                                    "additionalProperties": False,
                                },
                            }
                        },
                        "required": ["findings"],
                        "additionalProperties": False,
                    },
                },
            },
            "messages": [
                {
                    "role": "system",
                    "content": "You are a product-readiness UX review model. Return valid JSON only.",
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": self._build_prompt(page_url, viewport, page_type)},
                        {"type": "image_url", "image_url": {"url": self._load_image_data_url(image_path)}},
                    ],
                },
            ],
        }

        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            response_json = response.json()

        parsed = self._extract_json_payload(response_json)
        findings = parsed.get("findings") or []
        normalized = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            normalized.append(
                {
                    "scanner": "visual_ai",
                    "category": item.get("category") or "Visual UX",
                    "title": item.get("title") or "AI-assisted recommendation",
                    "severity": item.get("severity") or "recommendation",
                    "confidence": item.get("confidence") or "ai_assisted",
                    "page_url": page_url,
                    "viewport": viewport,
                    "selector": None,
                    "evidence": {
                        "rule_id": "visual-ai-review",
                        "description": item.get("observation") or "",
                    },
                    "user_impact": item.get("user_impact") or "",
                    "technical_remediation": item.get("technical_remediation") or "",
                    "builder_prompt": item.get("builder_prompt") or "",
                    "references": [],
                    "status": "open",
                }
            )
        return normalize_ux_findings(
            normalized,
            default_scanner="visual_ai",
            default_category="Visual UX",
        )


def build_visual_ai_provider() -> VisualAIProvider:
    provider = (settings.visual_ai_provider or "").strip().lower()
    enabled = settings.visual_ai_enabled
    if not enabled:
        return NoOpVisualAIProvider()

    if provider in {"openai", "openai_compatible"}:
        return OpenAICompatibleVisualAIProvider(
            api_key=settings.visual_ai_api_key or "",
            model=settings.visual_ai_model or "",
            base_url=settings.visual_ai_base_url,
            timeout_seconds=settings.visual_ai_timeout_seconds,
        )

    return NoOpVisualAIProvider()
