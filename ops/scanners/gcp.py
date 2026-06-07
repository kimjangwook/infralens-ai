from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone

import google.auth.transport.requests
from google.oauth2 import service_account
from requests import Session

from ops.detectors import classify_log_message
from ops.models import CloudAccount, Finding, ScanRun

from .common import UpsertCounter, upsert_finding, upsert_resource, upsert_schedule


DEFAULT_GCP_LOCATIONS = ["asia-northeast1", "us-central1"]
SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]


def scan_gcp(account: CloudAccount, credentials: dict, scan_run: ScanRun) -> dict:
    project_id = account.account_ref or credentials.get("project_id", "")
    if not project_id:
        raise ValueError("GCP project id is required.")

    locations = account.regions or DEFAULT_GCP_LOCATIONS
    authed_session = _authorized_session(credentials)
    counter = UpsertCounter()

    for location in locations:
        _scan_scheduler(account, authed_session, project_id, location, scan_run, counter)
        _scan_cloud_run(account, authed_session, project_id, location, counter)

    _scan_logging(account, authed_session, project_id, scan_run, counter)
    _add_gcp_billing_note(account, scan_run, counter)
    return {
        "provider": "gcp",
        "project_id": project_id,
        "locations": locations,
        "resources": counter.resources,
        "schedules": counter.schedules,
        "findings": counter.findings,
    }


def _authorized_session(credentials: dict) -> Session:
    creds = service_account.Credentials.from_service_account_info(
        credentials,
        scopes=SCOPES,
    )
    request = google.auth.transport.requests.Request()
    creds.refresh(request)
    session = Session()
    session.headers.update({"Authorization": f"Bearer {creds.token}"})
    return session


def _scan_scheduler(
    account: CloudAccount,
    session: Session,
    project_id: str,
    location: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    url = (
        "https://cloudscheduler.googleapis.com/v1/"
        f"projects/{project_id}/locations/{location}/jobs"
    )
    response = session.get(url, timeout=20)
    if response.status_code in {403, 404}:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "schedule",
            f"GCP Cloud Scheduler could not be scanned in {location}",
            evidence={"status_code": response.status_code, "location": location},
            suggested_action="Enable Cloud Scheduler API and grant cloudscheduler.jobs.list.",
        )
        counter.findings += 1
        return
    response.raise_for_status()
    for job in response.json().get("jobs", []):
        target_ref, target_type = _scheduler_target(job)
        upsert_schedule(
            account,
            job.get("name", ""),
            job.get("name", "").rsplit("/", 1)[-1],
            location,
            job.get("schedule", ""),
            job.get("state", ""),
            target_type,
            target_ref,
            {"time_zone": job.get("timeZone"), "retry_config": job.get("retryConfig", {})},
        )
        counter.schedules += 1
        if job.get("state") == "PAUSED":
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.INFO,
                "schedule",
                f"Cloud Scheduler job '{job.get('name', '').rsplit('/', 1)[-1]}' is paused",
                resource_ref=job.get("name", ""),
                evidence={"location": location, "schedule": job.get("schedule", "")},
                suggested_action="Verify whether this scheduled operation is intentionally paused.",
            )
            counter.findings += 1


def _scan_cloud_run(
    account: CloudAccount,
    session: Session,
    project_id: str,
    location: str,
    counter: UpsertCounter,
) -> None:
    for resource_kind, path in (
        ("gcp.cloud_run.service", "services"),
        ("gcp.cloud_run.job", "jobs"),
    ):
        url = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{location}/{path}"
        response = session.get(url, timeout=20)
        if response.status_code in {403, 404}:
            continue
        response.raise_for_status()
        key = path
        for item in response.json().get(key, []):
            name = item.get("name", "")
            upsert_resource(
                account,
                name,
                resource_kind,
                name.rsplit("/", 1)[-1],
                location,
                {
                    "create_time": item.get("createTime"),
                    "update_time": item.get("updateTime"),
                    "labels": item.get("labels", {}),
                },
            )
            counter.resources += 1


def _scan_logging(
    account: CloudAccount,
    session: Session,
    project_id: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    since = (datetime.now(dt_timezone.utc) - timedelta(hours=24)).isoformat()
    url = "https://logging.googleapis.com/v2/entries:list"
    payload = {
        "resourceNames": [f"projects/{project_id}"],
        "filter": f'timestamp >= "{since}" AND severity >= ERROR',
        "pageSize": 25,
    }
    response = session.post(url, json=payload, timeout=30)
    if response.status_code in {403, 404}:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "logs",
            "GCP Cloud Logging could not be scanned",
            evidence={"status_code": response.status_code},
            suggested_action="Grant logging.logEntries.list if log anomaly briefing is required.",
        )
        counter.findings += 1
        return
    response.raise_for_status()
    entries = response.json().get("entries", [])
    if not entries:
        return
    sample_text = _entry_text(entries[0])[:500]
    upsert_finding(
        account,
        scan_run,
        Finding.Severity.WARNING,
        "logs",
        "GCP project has recent error logs",
        resource_ref=f"projects/{project_id}",
        evidence={
            "project_id": project_id,
            "matched_entries_sampled": len(entries),
            "sample_type": classify_log_message(sample_text),
            "sample": sample_text,
        },
        suggested_action="Inspect failing scheduled jobs or Cloud Run services from the same period.",
    )
    counter.findings += 1


def _add_gcp_billing_note(account: CloudAccount, scan_run: ScanRun, counter: UpsertCounter) -> None:
    upsert_finding(
        account,
        scan_run,
        Finding.Severity.INFO,
        "cost",
        "GCP cost scan requires Billing Export",
        evidence={"mode": "not_configured"},
        suggested_action=(
            "Connect a BigQuery Billing Export table in a later setup step to enable "
            "service-level cost anomaly briefing."
        ),
    )
    counter.findings += 1


def _scheduler_target(job: dict) -> tuple[str, str]:
    if "httpTarget" in job:
        return job["httpTarget"].get("uri", ""), "gcp.http"
    if "pubsubTarget" in job:
        return job["pubsubTarget"].get("topicName", ""), "gcp.pubsub"
    if "appEngineHttpTarget" in job:
        return job["appEngineHttpTarget"].get("relativeUri", ""), "gcp.appengine"
    return "", ""


def _entry_text(entry: dict) -> str:
    for key in ("textPayload", "jsonPayload", "protoPayload"):
        if key in entry:
            return str(entry[key])
    return str(entry)

