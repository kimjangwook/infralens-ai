from __future__ import annotations

"""Read-only Azure scanner using a service principal and the ARM REST API.

Covers Function/Web Apps, Logic App workflows (Azure's closest analog to
scheduled jobs), and Activity Log errors. No Azure SDK dependency.
"""

from datetime import datetime, timedelta, timezone as dt_timezone

import requests
from requests import Session

from ops.detectors import classify_log_message
from ops.models import CloudAccount, Finding, ScanRun

from .common import UpsertCounter, upsert_finding, upsert_resource, upsert_schedule


MANAGEMENT = "https://management.azure.com"


def scan_azure(account: CloudAccount, credentials: dict, scan_run: ScanRun) -> dict:
    subscription_id = credentials.get("subscription_id") or account.account_ref
    if not subscription_id:
        raise ValueError("Azure subscription id is required.")

    session = _authorized_session(credentials)
    counter = UpsertCounter()

    _scan_sites(account, session, subscription_id, scan_run, counter)
    _scan_logic_apps(account, session, subscription_id, scan_run, counter)
    _scan_activity_log(account, session, subscription_id, scan_run, counter)
    return {
        "provider": "azure",
        "subscription_id": subscription_id,
        "resources": counter.resources,
        "schedules": counter.schedules,
        "findings": counter.findings,
    }


def _authorized_session(credentials: dict) -> Session:
    tenant = credentials.get("tenant_id", "")
    response = requests.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": credentials.get("client_id", ""),
            "client_secret": credentials.get("client_secret", ""),
            "scope": f"{MANAGEMENT}/.default",
        },
        timeout=20,
    )
    response.raise_for_status()
    token = response.json().get("access_token", "")
    if not token:
        raise ValueError("Azure token request returned no access token.")
    session = Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    return session


def _scan_sites(
    account: CloudAccount,
    session: Session,
    subscription_id: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    url = (
        f"{MANAGEMENT}/subscriptions/{subscription_id}/providers/"
        "Microsoft.Web/sites?api-version=2023-12-01"
    )
    response = session.get(url, timeout=30)
    if response.status_code in {403, 404}:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "schedule",
            "Azure Web/Function Apps could not be listed",
            evidence={"status_code": response.status_code},
            suggested_action="Grant the Reader role on the subscription to the service principal.",
        )
        counter.findings += 1
        return
    response.raise_for_status()
    for site in response.json().get("value", []):
        properties = site.get("properties", {})
        name = site.get("name", "")
        kind = site.get("kind", "") or ""
        resource_kind = "azure.function_app" if "functionapp" in kind else "azure.web_app"
        state = properties.get("state", "")
        upsert_resource(
            account,
            site.get("id", name),
            resource_kind,
            name,
            site.get("location", ""),
            {"state": state, "kind": kind, "default_host": properties.get("defaultHostName")},
        )
        counter.resources += 1
        if state and state != "Running":
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.WARNING,
                "schedule",
                f"Azure app '{name}' is {state.lower()}",
                resource_ref=site.get("id", name),
                evidence={"state": state, "kind": kind},
                suggested_action="Verify whether this app is intentionally stopped.",
            )
            counter.findings += 1


def _scan_logic_apps(
    account: CloudAccount,
    session: Session,
    subscription_id: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    url = (
        f"{MANAGEMENT}/subscriptions/{subscription_id}/providers/"
        "Microsoft.Logic/workflows?api-version=2019-05-01"
    )
    response = session.get(url, timeout=30)
    if response.status_code in {403, 404}:
        return
    response.raise_for_status()
    for workflow in response.json().get("value", []):
        properties = workflow.get("properties", {})
        name = workflow.get("name", "")
        state = properties.get("state", "")
        upsert_schedule(
            account,
            workflow.get("id", name),
            name,
            workflow.get("location", ""),
            "",  # recurrence lives inside the definition; not expanded here
            state.upper(),
            "azure.logic_app",
            workflow.get("id", ""),
            {"state": state},
        )
        counter.schedules += 1
        if state and state.lower() != "enabled":
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.INFO,
                "schedule",
                f"Logic App '{name}' is {state.lower()}",
                resource_ref=workflow.get("id", name),
                evidence={"state": state},
                suggested_action="Verify whether this workflow is intentionally disabled.",
            )
            counter.findings += 1


def _scan_activity_log(
    account: CloudAccount,
    session: Session,
    subscription_id: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    since = (datetime.now(dt_timezone.utc) - timedelta(hours=24)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    url = (
        f"{MANAGEMENT}/subscriptions/{subscription_id}/providers/"
        "Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01"
        f"&$filter=eventTimestamp ge '{since}' and levels eq 'Error'"
        "&$select=operationName,status,eventTimestamp,resourceId"
    )
    response = session.get(url, timeout=30)
    if response.status_code in {403, 404}:
        return
    response.raise_for_status()
    events = response.json().get("value", [])[:25]
    if not events:
        return
    first = events[0]
    sample = str(first.get("operationName", {}).get("localizedValue", ""))[:500]
    upsert_finding(
        account,
        scan_run,
        Finding.Severity.WARNING,
        "logs",
        "Azure subscription has recent error-level activity",
        resource_ref=f"subscriptions/{subscription_id}",
        evidence={
            "sampled_events": len(events),
            "sample_type": classify_log_message(sample),
            "sample_operation": sample,
            "sample_resource": str(first.get("resourceId", ""))[:300],
        },
        suggested_action="Inspect the Activity Log for failing deployments or operations.",
    )
    counter.findings += 1
