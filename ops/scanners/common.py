from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Any

from django.utils import timezone

from ops.detectors import mask_secrets
from ops.models import CloudAccount, Finding, Resource, ScanRun, Schedule


@dataclass
class UpsertCounter:
    resources: int = 0
    schedules: int = 0
    findings: int = 0


def upsert_resource(
    account: CloudAccount,
    provider_id: str,
    resource_type: str,
    name: str,
    region: str = "",
    metadata: dict | None = None,
) -> Resource:
    resource, _ = Resource.objects.update_or_create(
        account=account,
        provider_id=provider_id,
        defaults={
            "resource_type": resource_type,
            "name": name,
            "region": region,
            "metadata": mask_secrets(metadata or {}),
            "last_seen_at": timezone.now(),
        },
    )
    return resource


def upsert_schedule(
    account: CloudAccount,
    provider_id: str,
    name: str,
    region: str = "",
    schedule_expression: str = "",
    state: str = "",
    target_type: str = "",
    target_ref: str = "",
    metadata: dict | None = None,
) -> Schedule:
    schedule, _ = Schedule.objects.update_or_create(
        account=account,
        provider_id=provider_id,
        defaults={
            "name": name,
            "region": region,
            "schedule_expression": schedule_expression,
            "state": state,
            "target_type": target_type,
            "target_ref": target_ref,
            "metadata": mask_secrets(metadata or {}),
            "last_seen_at": timezone.now(),
        },
    )
    return schedule


def upsert_finding(
    account: CloudAccount,
    scan_run: ScanRun,
    severity: str,
    category: str,
    title: str,
    resource_ref: str = "",
    evidence: dict | None = None,
    suggested_action: str = "",
) -> Finding:
    finding, created = Finding.objects.update_or_create(
        account=account,
        category=category,
        title=title[:240],
        resource_ref=resource_ref,
        status=Finding.Status.OPEN,
        defaults={
            "scan_run": scan_run,
            "severity": severity,
            "evidence": mask_secrets(evidence or {}),
            "suggested_action": suggested_action,
            "last_seen_at": timezone.now(),
        },
    )
    if created:
        finding.first_seen_at = finding.last_seen_at
        finding.save(update_fields=["first_seen_at"])
    return finding


def recent_window_start(hours: int = 24):
    return timezone.now() - timedelta(hours=hours)


def decimal_from_cost(value: Any) -> Decimal:
    try:
        return Decimal(str(value))
    except Exception:  # noqa: BLE001
        return Decimal("0")

