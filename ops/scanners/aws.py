from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from ops.detectors import classify_log_message
from ops.models import CloudAccount, Finding, ScanRun

from .common import (
    UpsertCounter,
    decimal_from_cost,
    recent_window_start,
    upsert_finding,
    upsert_resource,
    upsert_schedule,
)


DEFAULT_AWS_REGIONS = ["ap-northeast-1", "us-east-1"]
LOG_FILTER = "?ERROR ?Error ?Exception ?timeout ?Timeout ?AccessDenied ?PermissionDenied"


def _session(credentials: dict, region: str):
    kwargs = {
        "aws_access_key_id": credentials["aws_access_key_id"],
        "aws_secret_access_key": credentials["aws_secret_access_key"],
        "region_name": region,
    }
    if credentials.get("aws_session_token"):
        kwargs["aws_session_token"] = credentials["aws_session_token"]
    return boto3.Session(**kwargs)


def scan_aws(account: CloudAccount, credentials: dict, scan_run: ScanRun) -> dict:
    regions = account.regions or DEFAULT_AWS_REGIONS
    counter = UpsertCounter()
    lambda_names_by_arn: dict[str, str] = {}

    for region in regions:
        session = _session(credentials, region)
        _scan_lambdas(account, session, region, counter, lambda_names_by_arn)
        _scan_eventbridge(account, session, region, scan_run, counter)
        _scan_lambda_logs(account, session, region, scan_run, counter, lambda_names_by_arn)

    _scan_cost_explorer(account, credentials, scan_run, counter)
    _scan_s3_exposure(account, credentials, scan_run, counter)
    return {
        "provider": "aws",
        "regions": regions,
        "resources": counter.resources,
        "schedules": counter.schedules,
        "findings": counter.findings,
    }


def _scan_lambdas(
    account: CloudAccount,
    session,
    region: str,
    counter: UpsertCounter,
    lambda_names_by_arn: dict[str, str],
) -> None:
    client = session.client("lambda")
    marker = None
    while True:
        kwargs = {"Marker": marker} if marker else {}
        response = client.list_functions(**kwargs)
        for item in response.get("Functions", []):
            arn = item.get("FunctionArn", "")
            name = item.get("FunctionName", arn.rsplit(":", 1)[-1])
            lambda_names_by_arn[arn] = name
            upsert_resource(
                account,
                arn,
                "aws.lambda",
                name,
                region,
                {
                    "runtime": item.get("Runtime"),
                    "memory_size": item.get("MemorySize"),
                    "timeout": item.get("Timeout"),
                    "last_modified": item.get("LastModified"),
                    "iam_role": item.get("Role", ""),
                },
            )
            counter.resources += 1
        marker = response.get("NextMarker")
        if not marker:
            break


def _scan_eventbridge(
    account: CloudAccount,
    session,
    region: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    client = session.client("events")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        response = client.list_rules(**kwargs)
        for rule in response.get("Rules", []):
            rule_name = rule.get("Name", "")
            targets = client.list_targets_by_rule(Rule=rule_name).get("Targets", [])
            target = targets[0] if targets else {}
            target_arn = target.get("Arn", "")
            target_type = _aws_target_type(target_arn)
            upsert_schedule(
                account,
                rule.get("Arn", f"{region}:{rule_name}"),
                rule_name,
                region,
                rule.get("ScheduleExpression", ""),
                rule.get("State", ""),
                target_type,
                target_arn,
                {"targets": targets, "description": rule.get("Description", "")},
            )
            counter.schedules += 1
            if rule.get("State") == "DISABLED":
                upsert_finding(
                    account,
                    scan_run,
                    Finding.Severity.INFO,
                    "schedule",
                    f"EventBridge rule '{rule_name}' is disabled",
                    resource_ref=rule.get("Arn", ""),
                    evidence={"region": region, "state": "DISABLED"},
                    suggested_action="Verify whether this schedule is intentionally paused.",
                )
                counter.findings += 1
            if not targets:
                upsert_finding(
                    account,
                    scan_run,
                    Finding.Severity.WARNING,
                    "schedule",
                    f"EventBridge rule '{rule_name}' has no targets",
                    resource_ref=rule.get("Arn", ""),
                    evidence={"region": region, "schedule": rule.get("ScheduleExpression", "")},
                    suggested_action="Attach an expected target or remove the unused schedule.",
                )
                counter.findings += 1
        next_token = response.get("NextToken")
        if not next_token:
            break


def _scan_lambda_logs(
    account: CloudAccount,
    session,
    region: str,
    scan_run: ScanRun,
    counter: UpsertCounter,
    lambda_names_by_arn: dict[str, str],
) -> None:
    logs = session.client("logs")
    start_time = int(recent_window_start(24).timestamp() * 1000)
    for function_name in set(lambda_names_by_arn.values()):
        log_group = f"/aws/lambda/{function_name}"
        try:
            response = logs.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                filterPattern=LOG_FILTER,
                limit=25,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ResourceNotFoundException", "AccessDeniedException"}:
                continue
            raise
        events = response.get("events", [])
        if not events:
            continue
        sample = events[0].get("message", "")[:500]
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.WARNING,
            "logs",
            f"Lambda '{function_name}' has recent error logs",
            resource_ref=log_group,
            evidence={
                "region": region,
                "log_group": log_group,
                "sample_type": classify_log_message(sample),
                "sample": sample,
                "matched_events": len(events),
            },
            suggested_action="Check recent invocations, timeout settings, and upstream schedule.",
        )
        counter.findings += 1


def _scan_cost_explorer(
    account: CloudAccount,
    credentials: dict,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    session = _session(credentials, "us-east-1")
    client = session.client("ce")
    today = datetime.now(dt_timezone.utc).date()
    yesterday = today - timedelta(days=1)
    baseline_start = today - timedelta(days=8)
    baseline_end = yesterday

    try:
        yesterday_costs = _cost_by_service(client, yesterday.isoformat(), today.isoformat())
        baseline_costs = _cost_by_service(client, baseline_start.isoformat(), baseline_end.isoformat())
    except (ClientError, BotoCoreError) as exc:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "cost",
            "AWS Cost Explorer could not be scanned",
            evidence={"error": str(exc)[:500]},
            suggested_action="Grant ce:GetCostAndUsage to the read-only role if cost briefing is required.",
        )
        counter.findings += 1
        return

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
                f"AWS cost spike in {service}",
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


def _scan_s3_exposure(
    account: CloudAccount,
    credentials: dict,
    scan_run: ScanRun,
    counter: UpsertCounter,
) -> None:
    session = _session(credentials, "us-east-1")
    client = session.client("s3")
    try:
        buckets = client.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError) as exc:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "exposure",
            "AWS S3 could not be scanned",
            evidence={"error": str(exc)[:500]},
            suggested_action="Grant s3:ListAllMyBuckets and s3:GetBucket* to enable exposure checks.",
        )
        counter.findings += 1
        return

    for bucket in buckets[:200]:
        name = bucket.get("Name", "")
        if not name:
            continue
        upsert_resource(
            account,
            f"arn:aws:s3:::{name}",
            "aws.s3_bucket",
            name,
            "",
            {"creation_date": str(bucket.get("CreationDate", ""))},
        )
        counter.resources += 1

        is_public, pab_gaps = _bucket_public_state(client, name)
        if is_public:
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.CRITICAL,
                "exposure",
                f"S3 bucket '{name}' is publicly accessible",
                resource_ref=f"arn:aws:s3:::{name}",
                evidence={"bucket": name, "policy_status": "public"},
                suggested_action=(
                    "Enable the account/bucket public access block and remove public "
                    "statements from the bucket policy unless this bucket is a website."
                ),
            )
            counter.findings += 1
        elif pab_gaps:
            upsert_finding(
                account,
                scan_run,
                Finding.Severity.WARNING,
                "exposure",
                f"S3 bucket '{name}' has no complete public access block",
                resource_ref=f"arn:aws:s3:::{name}",
                evidence={"bucket": name, "public_access_block_gaps": pab_gaps},
                suggested_action="Enable all four public access block settings for this bucket.",
            )
            counter.findings += 1


def _bucket_public_state(client, name: str) -> tuple[bool, list[str]]:
    """Return (is_public, public-access-block gaps) for one bucket."""
    is_public = False
    gaps: list[str] = []
    try:
        status = client.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
        is_public = bool(status.get("IsPublic"))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {"NoSuchBucketPolicy", "AccessDenied"}:
            raise
    try:
        pab = client.get_public_access_block(Bucket=name).get(
            "PublicAccessBlockConfiguration", {}
        )
        gaps = [key for key, enabled in pab.items() if not enabled]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchPublicAccessBlockConfiguration":
            gaps = ["NoPublicAccessBlockConfiguration"]
        elif code != "AccessDenied":
            raise
    return is_public, gaps


def _cost_by_service(client, start: str, end: str) -> dict[str, Decimal]:
    response = client.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    totals: dict[str, Decimal] = {}
    for result in response.get("ResultsByTime", []):
        for group in result.get("Groups", []):
            service = group.get("Keys", ["Unknown"])[0]
            amount = group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", "0")
            totals[service] = totals.get(service, Decimal("0")) + decimal_from_cost(amount)
    return totals


def _aws_target_type(arn: str) -> str:
    if ":lambda:" in arn:
        return "aws.lambda"
    if ":ecs:" in arn:
        return "aws.ecs"
    if ":states:" in arn:
        return "aws.stepfunctions"
    if ":sqs:" in arn:
        return "aws.sqs"
    if ":sns:" in arn:
        return "aws.sns"
    return "aws.target" if arn else ""

