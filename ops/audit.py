from __future__ import annotations

"""Audit trail helpers and login/logout signal hooks."""

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver

from .models import AuditLog


def record_audit(user, action: str, target: str = "", **metadata) -> AuditLog:
    return AuditLog.objects.create(
        user=user if getattr(user, "is_authenticated", False) else None,
        action=action,
        target=str(target)[:300],
        metadata=metadata,
    )


@receiver(user_logged_in)
def _on_login(sender, request, user, **kwargs):
    record_audit(user, "login")


@receiver(user_logged_out)
def _on_logout(sender, request, user, **kwargs):
    if user is not None:
        record_audit(user, "logout")
