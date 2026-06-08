from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet
from django.conf import settings


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_json(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _fernet().encrypt(raw).decode("utf-8")


def decrypt_json(token: str) -> dict:
    if not token:
        return {}
    raw = _fernet().decrypt(token.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))


def encrypt_text(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_text(token: str) -> str:
    if not token:
        return ""
    return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")


def secret_hint(value: str) -> str:
    """Return a masked hint for a secret such as an API key."""
    value = value.strip()
    if len(value) >= 8:
        return f"{value[:4]}...{value[-4:]}"
    if value:
        return "****"
    return ""


def credential_hint(provider: str, payload: dict) -> str:
    if provider == "aws":
        key = payload.get("aws_access_key_id", "")
        if len(key) >= 8:
            return f"{key[:4]}...{key[-4:]}"
        return "AWS static key"
    if provider == "gcp":
        email = payload.get("client_email") or payload.get("service_account_email", "")
        return email or "GCP service account"
    return "encrypted credentials"
