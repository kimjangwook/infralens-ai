from __future__ import annotations

import json
from typing import Any

import requests
from django.conf import settings

from .models import Finding, GlobalSettings


LANGUAGE_NAMES = {
    GlobalSettings.ReportLanguage.EN: "English",
    GlobalSettings.ReportLanguage.JA: "Japanese",
    GlobalSettings.ReportLanguage.KO: "Korean",
}


def generate_ai_insight(
    *,
    title_account: str,
    findings: list[Finding],
    report_language: str,
    model: str,
) -> tuple[str | None, dict[str, Any]]:
    if not settings.AI_ENABLED:
        return None, {"ai_status": "disabled"}
    if not settings.OPENAI_API_KEY:
        return None, {"ai_status": "missing_api_key"}

    language_name = LANGUAGE_NAMES.get(report_language, "English")
    payload = _finding_payload(findings)
    prompt = {
        "account_scope": title_account,
        "language": language_name,
        "findings": payload,
        "rules": [
            "Write the entire report in the configured language.",
            "Use only the provided evidence. Do not invent cloud resources, causes, or metrics.",
            "InfraLens is read-only. Suggested actions must be proposals only.",
            "Prioritize security and production-impacting failures before cost and informational items.",
            "Include confidence for each major insight as high, medium, or low.",
        ],
    }
    request_body = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": (
                    "You are InfraLens AI, a cautious CloudOps analyst for small teams. "
                    "You create evidence-backed daily cloud operations briefings."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(prompt, ensure_ascii=False),
            },
        ],
    }
    try:
        response = requests.post(
            "https://api.openai.com/v1/responses",
            headers={
                "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=request_body,
            timeout=45,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        return None, {
            "ai_status": "request_failed",
            "model": model,
            "error": str(exc)[:500],
        }

    text = _extract_response_text(data)
    if not text:
        return None, {"ai_status": "empty_response", "model": model}
    return text, {"ai_status": "generated", "model": model}


def _finding_payload(findings: list[Finding]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for finding in findings[:30]:
        items.append(
            {
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "account": finding.account.name,
                "resource_ref": finding.resource_ref,
                "evidence": finding.evidence,
                "suggested_action": finding.suggested_action,
                "last_seen_at": finding.last_seen_at.isoformat(),
            }
        )
    return items


def _extract_response_text(data: dict[str, Any]) -> str:
    if isinstance(data.get("output_text"), str):
        return data["output_text"].strip()
    chunks: list[str] = []
    for output in data.get("output", []):
        for content in output.get("content", []):
            if isinstance(content.get("text"), str):
                chunks.append(content["text"])
    return "\n".join(chunks).strip()

