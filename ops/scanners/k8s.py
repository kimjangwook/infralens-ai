from __future__ import annotations

"""Read-only Kubernetes scanner using the cluster REST API directly.

Credentials are an API server URL plus a bearer token for a read-only
ServiceAccount (view ClusterRole). No kubernetes client dependency.
"""

from requests import Session

from ops.detectors import classify_log_message
from ops.models import CloudAccount, Finding, ScanRun

from .common import UpsertCounter, upsert_finding, upsert_resource, upsert_schedule


def scan_k8s(account: CloudAccount, credentials: dict, scan_run: ScanRun) -> dict:
    api_server = (credentials.get("api_server") or "").rstrip("/")
    token = credentials.get("token", "")
    if not api_server or not token:
        raise ValueError("Kubernetes API server URL and bearer token are required.")

    session = Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    verify_tls = bool(credentials.get("verify_tls", True))
    counter = UpsertCounter()

    _scan_cronjobs(account, session, api_server, verify_tls, scan_run, counter)
    _scan_deployments(account, session, api_server, verify_tls, scan_run, counter)
    _scan_warning_events(account, session, api_server, verify_tls, scan_run, counter)
    return {
        "provider": "k8s",
        "api_server": api_server,
        "resources": counter.resources,
        "schedules": counter.schedules,
        "findings": counter.findings,
    }


def _get(session: Session, api_server: str, path: str, verify_tls: bool):
    return session.get(f"{api_server}{path}", timeout=20, verify=verify_tls)


def _scan_cronjobs(
    account: CloudAccount,
    session: Session,
    api_server: str,
    verify_tls: bool,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    response = _get(session, api_server, "/apis/batch/v1/cronjobs?limit=500", verify_tls)
    if response.status_code in {403, 404}:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "schedule",
            "Kubernetes CronJobs could not be listed",
            evidence={"status_code": response.status_code},
            suggested_action="Bind the view ClusterRole to the scanner ServiceAccount.",
        )
        counter.findings += 1
        return
    response.raise_for_status()
    for item in response.json().get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        namespace = meta.get("namespace", "default")
        name = meta.get("name", "")
        suspended = bool(spec.get("suspend"))
        containers = (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        image = containers[0].get("image", "") if containers else ""
        upsert_schedule(
            account,
            f"cronjob/{namespace}/{name}",
            name,
            namespace,
            spec.get("schedule", ""),
            "SUSPENDED" if suspended else "ACTIVE",
            "k8s.job",
            image,
            {"namespace": namespace, "concurrency_policy": spec.get("concurrencyPolicy")},
        )
        counter.schedules += 1
        if suspended:
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.INFO,
                "schedule",
                f"CronJob '{namespace}/{name}' is suspended",
                resource_ref=f"cronjob/{namespace}/{name}",
                evidence={"namespace": namespace, "schedule": spec.get("schedule", "")},
                suggested_action="Verify whether this CronJob is intentionally suspended.",
            )
            counter.findings += 1


def _scan_deployments(
    account: CloudAccount,
    session: Session,
    api_server: str,
    verify_tls: bool,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    response = _get(session, api_server, "/apis/apps/v1/deployments?limit=500", verify_tls)
    if response.status_code in {403, 404}:
        return
    response.raise_for_status()
    for item in response.json().get("items", []):
        meta = item.get("metadata", {})
        status = item.get("status", {})
        namespace = meta.get("namespace", "default")
        name = meta.get("name", "")
        desired = item.get("spec", {}).get("replicas", 0) or 0
        available = status.get("availableReplicas", 0) or 0
        upsert_resource(
            account,
            f"deployment/{namespace}/{name}",
            "k8s.deployment",
            name,
            namespace,
            {"replicas": desired, "available_replicas": available},
        )
        counter.resources += 1
        if desired > 0 and available < desired:
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.WARNING,
                "logs",
                f"Deployment '{namespace}/{name}' has unavailable replicas",
                resource_ref=f"deployment/{namespace}/{name}",
                evidence={"desired": desired, "available": available, "namespace": namespace},
                suggested_action="Check pod events, image pulls, and resource limits.",
            )
            counter.findings += 1


def _scan_warning_events(
    account: CloudAccount,
    session: Session,
    api_server: str,
    verify_tls: bool,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    response = _get(
        session,
        api_server,
        "/api/v1/events?fieldSelector=type%3DWarning&limit=25",
        verify_tls,
    )
    if response.status_code in {403, 404}:
        return
    response.raise_for_status()
    events = response.json().get("items", [])
    if not events:
        return
    first = events[0]
    sample = str(first.get("message", ""))[:500]
    upsert_finding(
        account,
        scan_run,
        Finding.Severity.WARNING,
        "logs",
        "Kubernetes cluster has recent warning events",
        resource_ref=api_server,
        evidence={
            "sampled_events": len(events),
            "sample_type": classify_log_message(sample),
            "sample": sample,
            "sample_reason": first.get("reason", ""),
            "sample_object": str(first.get("involvedObject", {}).get("name", "")),
        },
        suggested_action="Inspect the warning events for failing workloads or scheduling issues.",
    )
    counter.findings += 1
