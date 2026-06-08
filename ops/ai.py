from __future__ import annotations

import json
from typing import Any

import requests
from django.conf import settings

from .crypto import decrypt_text
from .models import AIProvider, Finding, GlobalSettings


LANGUAGE_NAMES = {
    GlobalSettings.ReportLanguage.EN: "English",
    GlobalSettings.ReportLanguage.JA: "Japanese",
    GlobalSettings.ReportLanguage.KO: "Korean",
}

SYSTEM_PROMPT = (
    "You are InfraLens AI, a cautious CloudOps analyst for small teams. "
    "You create evidence-backed daily cloud operations briefings."
)


def generate_ai_insight(
    *,
    title_account: str,
    findings: list[Finding],
    report_language: str,
    provider: AIProvider | None = None,
) -> tuple[str | None, dict[str, Any]]:
    if not settings.AI_ENABLED:
        return None, {"ai_status": "disabled"}
    if provider is None:
        provider = AIProvider.get_default()
    if provider is None:
        return None, {"ai_status": "no_provider"}

    api_key = decrypt_text(provider.encrypted_api_key)
    if not api_key:
        return None, {"ai_status": "missing_api_key", "provider": provider.provider}

    language_name = LANGUAGE_NAMES.get(report_language, "English")
    prompt = {
        "account_scope": title_account,
        "language": language_name,
        "findings": _finding_payload(findings),
        "rules": [
            "Write the entire report in the configured language.",
            "Use only the provided evidence. Do not invent cloud resources, causes, or metrics.",
            "InfraLens is read-only. Suggested actions must be proposals only.",
            "Prioritize security and production-impacting failures before cost and informational items.",
            "Include confidence for each major insight as high, medium, or low.",
        ],
    }
    user_content = json.dumps(prompt, ensure_ascii=False)

    meta_base = {"provider": provider.provider, "model": provider.model}
    try:
        if provider.provider == AIProvider.Provider.OPENAI:
            text = _call_openai(provider.model, api_key, user_content)
        elif provider.provider == AIProvider.Provider.ANTHROPIC:
            text = _call_anthropic(provider.model, api_key, user_content)
        elif provider.provider == AIProvider.Provider.GOOGLE:
            text = _call_google(provider.model, api_key, user_content)
        else:
            return None, {"ai_status": "unsupported_provider", **meta_base}
    except requests.RequestException as exc:
        return None, {"ai_status": "request_failed", "error": str(exc)[:500], **meta_base}

    if not text:
        return None, {"ai_status": "empty_response", **meta_base}
    return text, {"ai_status": "generated", **meta_base}


def verify_ai_provider(provider: AIProvider) -> tuple[bool, str]:
    """Send a minimal request to confirm the provider's key and model work.

    Returns (ok, message). Used by the "Test connection" action so an operator
    can confirm a newly added provider before a briefing depends on it.
    """
    api_key = decrypt_text(provider.encrypted_api_key)
    if not api_key:
        return False, "No API key is stored for this provider."

    probe = "Reply with the single word OK."
    try:
        if provider.provider == AIProvider.Provider.OPENAI:
            text = _call_openai(provider.model, api_key, probe)
        elif provider.provider == AIProvider.Provider.ANTHROPIC:
            text = _call_anthropic(provider.model, api_key, probe)
        elif provider.provider == AIProvider.Provider.GOOGLE:
            text = _call_google(provider.model, api_key, probe)
        else:
            return False, f"Unsupported provider: {provider.provider}"
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        detail = ""
        if exc.response is not None:
            detail = exc.response.text[:200]
        return False, f"HTTP {status} from {provider.get_provider_display()}. {detail}".strip()
    except requests.RequestException as exc:
        return False, f"Request failed: {str(exc)[:200]}"

    if not text:
        return False, "The provider returned an empty response."
    return True, f"OK - {provider.get_provider_display()} responded with {provider.model}."


def _call_openai(model: str, api_key: str, user_content: str) -> str:
    response = requests.post(
        "https://api.openai.com/v1/responses",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "input": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
        },
        timeout=45,
    )
    response.raise_for_status()
    return _extract_openai_text(response.json())


def _call_anthropic(model: str, api_key: str, user_content: str) -> str:
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 2048,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_content}],
        },
        timeout=45,
    )
    response.raise_for_status()
    return _extract_anthropic_text(response.json())


def _call_google(model: str, api_key: str, user_content: str) -> str:
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    )
    response = requests.post(
        url,
        headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
        json={
            "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": user_content}]}],
        },
        timeout=45,
    )
    response.raise_for_status()
    return _extract_google_text(response.json())


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


def _extract_openai_text(data: dict[str, Any]) -> str:
    if isinstance(data.get("output_text"), str):
        return data["output_text"].strip()
    chunks: list[str] = []
    for output in data.get("output", []):
        for content in output.get("content", []):
            if isinstance(content.get("text"), str):
                chunks.append(content["text"])
    return "\n".join(chunks).strip()


def _extract_anthropic_text(data: dict[str, Any]) -> str:
    chunks: list[str] = []
    for block in data.get("content", []):
        if isinstance(block.get("text"), str):
            chunks.append(block["text"])
    return "\n".join(chunks).strip()


def _extract_google_text(data: dict[str, Any]) -> str:
    chunks: list[str] = []
    for candidate in data.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            if isinstance(part.get("text"), str):
                chunks.append(part["text"])
    return "\n".join(chunks).strip()
