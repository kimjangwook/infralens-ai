from __future__ import annotations

from django.utils import timezone

from ops.crypto import decrypt_json
from ops.models import CloudAccount, ScanRun


def run_scan(account: CloudAccount) -> ScanRun:
    credentials = decrypt_json(account.encrypted_credentials)
    scan_run = ScanRun.objects.create(account=account)
    scan_run.mark_running()
    try:
        if account.provider == CloudAccount.Provider.AWS:
            from .aws import scan_aws

            summary = scan_aws(account, credentials, scan_run)
        elif account.provider == CloudAccount.Provider.GCP:
            from .gcp import scan_gcp

            summary = scan_gcp(account, credentials, scan_run)
        else:
            raise ValueError(f"Unsupported provider: {account.provider}")
    except Exception as exc:  # noqa: BLE001 - scanner failures must be visible in UI.
        scan_run.mark_failed(str(exc))
        return scan_run

    from ops.topology import analyze_topology

    summary["topology_findings"] = analyze_topology(account, scan_run)
    summary["finished_at"] = timezone.now().isoformat()
    scan_run.mark_success(summary)
    return scan_run

