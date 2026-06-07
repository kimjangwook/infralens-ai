from __future__ import annotations

import re
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(secret|token|password|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
]

ERROR_TERMS = (
    "error",
    "exception",
    "timeout",
    "timed out",
    "accessdenied",
    "permissiondenied",
    "5xx",
)


def mask_secrets(value: Any) -> Any:
    if isinstance(value, str):
        masked = value
        for pattern in SECRET_PATTERNS:
            masked = pattern.sub("[masked-secret]", masked)
        return masked
    if isinstance(value, list):
        return [mask_secrets(item) for item in value]
    if isinstance(value, dict):
        return {key: mask_secrets(item) for key, item in value.items()}
    return value


def contains_error(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in ERROR_TERMS)


def classify_log_message(text: str) -> str:
    lowered = text.lower()
    if "accessdenied" in lowered or "permissiondenied" in lowered:
        return "permission"
    if "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    if "5xx" in lowered or " 500 " in lowered or " 502 " in lowered or " 503 " in lowered:
        return "5xx"
    if "exception" in lowered:
        return "exception"
    return "error"

