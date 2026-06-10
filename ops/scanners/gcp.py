from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone as dt_timezone
from decimal import Decimal

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
    _scan_gcs_exposure(account, authed_session, project_id, scan_run, counter)
    billing_table = (account.options or {}).get("gcp_billing_export_table", "")
    if billing_table:
        _scan_billing_export(account, authed_session, project_id, billing_table, scan_run, counter)
    else:
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


def _scan_gcs_exposure(
    account: CloudAccount,
    session: Session,
    project_id: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    url = f"https://storage.googleapis.com/storage/v1/b?project={project_id}&projection=full"
    response = session.get(url, timeout=20)
    if response.status_code in {403, 404}:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "exposure",
            "GCP Cloud Storage could not be scanned",
            evidence={"status_code": response.status_code},
            suggested_action="Grant storage.buckets.list and storage.buckets.getIamPolicy.",
        )
        counter.findings += 1
        return
    response.raise_for_status()
    for bucket in response.json().get("items", [])[:200]:
        name = bucket.get("name", "")
        if not name:
            continue
        prevention = (
            bucket.get("iamConfiguration", {}).get("publicAccessPrevention", "")
        )
        upsert_resource(
            account,
            f"gs://{name}",
            "gcp.gcs_bucket",
            name,
            bucket.get("location", "").lower(),
            {"storage_class": bucket.get("storageClass"), "public_access_prevention": prevention},
        )
        counter.resources += 1

        public_members = _public_iam_members(session, name)
        if public_members:
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.CRITICAL,
                "exposure",
                f"GCS bucket '{name}' is publicly accessible",
                resource_ref=f"gs://{name}",
                evidence={"bucket": name, "public_members": public_members},
                suggested_action=(
                    "Remove allUsers/allAuthenticatedUsers bindings and enforce "
                    "public access prevention unless this bucket hosts a website."
                ),
            )
            counter.findings += 1
        elif prevention and prevention != "enforced":
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.WARNING,
                "exposure",
                f"GCS bucket '{name}' does not enforce public access prevention",
                resource_ref=f"gs://{name}",
                evidence={"bucket": name, "public_access_prevention": prevention},
                suggested_action="Set publicAccessPrevention to 'enforced' on this bucket.",
            )
            counter.findings += 1


def _public_iam_members(session: Session, bucket_name: str) -> list[str]:
    response = session.get(
        f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/iam",
        timeout=20,
    )
    if response.status_code in {403, 404}:
        return []
    response.raise_for_status()
    members: list[str] = []
    for binding in response.json().get("bindings", []):
        for member in binding.get("members", []):
            if member in {"allUsers", "allAuthenticatedUsers"}:
                members.append(f"{member} ({binding.get('role', '')})")
    return members


BILLING_TABLE_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")


def _scan_billing_export(
    account: CloudAccount,
    session: Session,
    project_id: str,
    billing_table: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    if not BILLING_TABLE_PATTERN.match(billing_table):
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "cost",
            "GCP billing export table id is invalid",
            evidence={"table": billing_table},
            suggested_action="Use the project.dataset.table form for the billing export table.",
        )
        counter.findings += 1
        return

    query = (
        "SELECT service.description AS service, DATE(usage_start_time) AS day, "
        "SUM(cost) AS cost "
        f"FROM `{billing_table}` "
        "WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 9 DAY) "
        "GROUP BY service, day"
    )
    response = session.post(
        f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/queries",
        json={"query": query, "useLegacySql": False, "timeoutMs": 30000},
        timeout=45,
    )
    if response.status_code in {400, 403, 404}:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "cost",
            "GCP billing export could not be queried",
            evidence={"status_code": response.status_code, "table": billing_table},
            suggested_action=(
                "Verify the billing export table id and grant bigquery.jobs.create "
                "plus read access on the dataset."
            ),
        )
        counter.findings += 1
        return
    response.raise_for_status()

    today = datetime.now(dt_timezone.utc).date()
    yesterday = (today - timedelta(days=1)).isoformat()
    yesterday_costs: dict[str, Decimal] = {}
    baseline_costs: dict[str, Decimal] = {}
    for row in response.json().get("rows", []):
        cells = row.get("f", [])
        if len(cells) < 3:
            continue
        service = str(cells[0].get("v", "Unknown"))
        day = str(cells[1].get("v", ""))
        try:
            cost = Decimal(str(cells[2].get("v", "0")))
        except Exception:  # noqa: BLE001
            cost = Decimal("0")
        if day == yesterday:
            yesterday_costs[service] = yesterday_costs.get(service, Decimal("0")) + cost
        elif day < yesterday:
            baseline_costs[service] = baseline_costs.get(service, Decimal("0")) + cost

    for service, cost in yesterday_costs.items():
        baseline_avg = baseline_costs.get(service, Decimal("0")) / Decimal("7")
        if baseline_avg <= Decimal("0.01"):
            continue
        ratio = cost / baseline_avg
        if cost >= Decimal("1.00") and ratio >= Decimal("2.0"):
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.WARNING,
                "cost",
                f"GCP cost spike in {service}",
                resource_ref=service,
                evidence={
                    "service": service,
                    "yesterday_usd": str(cost.quantize(Decimal("0.01"))),
                    "seven_day_average_usd": str(baseline_avg.quantize(Decimal("0.01"))),
                    "ratio": str(ratio.quantize(Decimal("0.01"))),
                },
                suggested_action="Compare the service with scheduled jobs and recent deployments.",
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

