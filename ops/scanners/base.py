from __future__ import annotations

from django.utils import timezone

from ops.crypto import decrypt_json
from ops.models import CloudAccount, Finding, ScanRun


def run_scan(account: CloudAccount) -> ScanRun:
    credentials = decrypt_json(account.encrypted_credentials)
    scan_run = ScanRun.objects.create(account=account)
    scan_run.mark_running()
    had_previous_scan = account.last_scan_at is not None
    previous_resources = dict(account.resources.values_list("provider_id", "name"))
    previous_schedules = dict(account.schedules.values_list("provider_id", "name"))
    try:
        if account.provider == CloudAccount.Provider.AWS:
            from .aws import scan_aws

            summary = scan_aws(account, credentials, scan_run)
        elif account.provider == CloudAccount.Provider.GCP:
            from .gcp import scan_gcp

            summary = scan_gcp(account, credentials, scan_run)
        elif account.provider == CloudAccount.Provider.K8S:
            from .k8s import scan_k8s

            summary = scan_k8s(account, credentials, scan_run)
        elif account.provider == CloudAccount.Provider.AZURE:
            from .azure import scan_azure

            summary = scan_azure(account, credentials, scan_run)
        else:
            raise ValueError(f"Unsupported provider: {account.provider}")
    except Exception as exc:  # noqa: BLE001 - scanner failures must be visible in UI.
        scan_run.mark_failed(str(exc))
        return scan_run

    summary["changes"] = _apply_change_diff(
        account,
        scan_run,
        had_previous_scan,
        previous_resources,
        previous_schedules,
    )

    from ops.topology import analyze_topology

    summary["topology_findings"] = analyze_topology(account, scan_run)
    summary["finished_at"] = timezone.now().isoformat()
    scan_run.mark_success(summary)

    from ops.rules import evaluate_custom_rules

    evaluate_custom_rules(account, scan_run)
    return scan_run


def _apply_change_diff(
    account: CloudAccount,
    scan_run: ScanRun,
    had_previous_scan: bool,
    previous_resources: dict[str, str],
    previous_schedules: dict[str, str],
) -> dict:
    """Compare this scan's inventory with the previous one.

    Rows not refreshed by this scan are treated as gone and deleted, so the
    topology map always reflects the latest scan. Findings reference resources
    by string ref, so deleting stale snapshot rows is safe.
    """
    if scan_run.started_at is None:
        return {}

    stale_resources = account.resources.filter(last_seen_at__lt=scan_run.started_at)
    stale_schedules = account.schedules.filter(last_seen_at__lt=scan_run.started_at)
    removed_resources = [name for _, name in stale_resources.values_list("provider_id", "name")]
    removed_schedules = [name for _, name in stale_schedules.values_list("provider_id", "name")]
    stale_resources.delete()
    stale_schedules.delete()

    current_resources = set(account.resources.values_list("provider_id", flat=True))
    current_schedules = set(account.schedules.values_list("provider_id", flat=True))
    added_resources = sorted(
        account.resources.filter(
            provider_id__in=current_resources - set(previous_resources)
        ).values_list("name", flat=True)
    )
    added_schedules = sorted(
        account.schedules.filter(
            provider_id__in=current_schedules - set(previous_schedules)
        ).values_list("name", flat=True)
    )

    changes = {
        "resources_added": added_resources[:50],
        "resources_removed": sorted(removed_resources)[:50],
        "schedules_added": added_schedules[:50],
        "schedules_removed": sorted(removed_schedules)[:50],
    }

    changed = any(changes.values())
    if changed and had_previous_scan:
        from .common import upsert_finding

        total = sum(len(value) for value in changes.values())
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "change",
            f"{total} inventory change(s) since the previous scan",
            evidence=changes,
            suggested_action=(
                "Review whether the added and removed resources and schedules "
                "match expected deployments."
            ),
        )
    return changes
