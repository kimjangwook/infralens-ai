from __future__ import annotations

from collections import defaultdict
from typing import Iterable

import requests
from django.db.models import Count, Q

from .ai import generate_ai_insight
from .authz import has_account_role
from .crypto import decrypt_text, encrypt_json
from .models import (
    AccountMembership,
    CloudAccount,
    DailyBriefing,
    Finding,
    GlobalSettings,
    NotificationDelivery,
    NotificationSubscription,
    Resource,
    Schedule,
    ScanRun,
)


SEVERITY_ORDER = {
    Finding.Severity.CRITICAL: 0,
    Finding.Severity.WARNING: 1,
    Finding.Severity.INFO: 2,
    Finding.Severity.OK: 3,
}


def dashboard_stats(accounts=None) -> dict:
    accounts = accounts if accounts is not None else CloudAccount.objects.all()
    open_findings = Finding.objects.filter(account__in=accounts, status=Finding.Status.OPEN)
    return {
        "accounts": accounts.count(),
        "resources": Resource.objects.filter(account__in=accounts).count(),
        "schedules": Schedule.objects.filter(account__in=accounts).count(),
        "critical": open_findings.filter(severity=Finding.Severity.CRITICAL).count(),
        "warnings": open_findings.filter(severity=Finding.Severity.WARNING).count(),
        "cost_findings": open_findings.filter(category="cost").count(),
        "failed_schedules": open_findings.filter(
            Q(category="schedule") | Q(category="logs"),
            severity__in=[Finding.Severity.CRITICAL, Finding.Severity.WARNING],
        ).count(),
    }


def account_stats(account: CloudAccount) -> dict:
    open_findings = account.findings.filter(status=Finding.Status.OPEN)
    return {
        "resources": account.resources.count(),
        "schedules": account.schedules.count(),
        "critical": open_findings.filter(severity=Finding.Severity.CRITICAL).count(),
        "warnings": open_findings.filter(severity=Finding.Severity.WARNING).count(),
        "scan_runs": account.scan_runs.count(),
    }


def finding_summary_by_category(accounts=None) -> Iterable[dict]:
    accounts = accounts if accounts is not None else CloudAccount.objects.all()
    return (
        Finding.objects.filter(account__in=accounts, status=Finding.Status.OPEN)
        .values("category", "severity")
        .annotate(total=Count("id"))
        .order_by("category", "severity")
    )


FALLBACK_LABELS = {
    GlobalSettings.ReportLanguage.EN: {
        "title": "Daily Infra Briefing",
        "read_only": "InfraLens is read-only. Suggested actions are proposals, not automatic changes.",
        "critical": "Critical",
        "warning": "Warning",
        "review": "Review",
        "no_items": "No open items.",
        "account": "Account",
        "resource": "Resource",
        "suggested_action": "Suggested action",
    },
    GlobalSettings.ReportLanguage.JA: {
        "title": "Daily Infra Briefing",
        "read_only": "InfraLens は読み取り専用です。提案された対応は自動実行されません。",
        "critical": "Critical",
        "warning": "Warning",
        "review": "Review",
        "no_items": "未対応の項目はありません。",
        "account": "アカウント",
        "resource": "リソース",
        "suggested_action": "推奨対応",
    },
    GlobalSettings.ReportLanguage.KO: {
        "title": "Daily Infra Briefing",
        "read_only": "InfraLens는 읽기 전용입니다. 제안된 조치는 자동 실행되지 않습니다.",
        "critical": "긴급",
        "warning": "주의",
        "review": "검토",
        "no_items": "열린 항목이 없습니다.",
        "account": "계정",
        "resource": "리소스",
        "suggested_action": "제안 조치",
    },
}


def get_global_settings() -> GlobalSettings:
    return GlobalSettings.load()


def generate_daily_briefing(
    account: CloudAccount | None = None,
    *,
    use_ai: bool = True,
) -> DailyBriefing:
    global_settings = get_global_settings()
    findings = Finding.objects.filter(status=Finding.Status.OPEN)
    title_account = "All accounts"
    if account:
        findings = findings.filter(account=account)
        title_account = account.name

    ordered = sorted(
        findings.select_related("account")[:100],
        key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.category, item.title),
    )
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in ordered:
        groups[finding.severity].append(finding)

    ai_meta = {"ai_status": "not_requested"}
    body = None
    if use_ai:
        body, ai_meta = generate_ai_insight(
            title_account=title_account,
            findings=ordered,
            report_language=global_settings.report_language,
            model=global_settings.ai_model,
        )
    if body is None:
        body = _fallback_briefing(
            title_account=title_account,
            groups=groups,
            language=global_settings.report_language,
        )

    evidence = {
        "finding_ids": [str(finding.id) for finding in ordered[:30]],
        "open_findings": len(ordered),
        "report_language": global_settings.report_language,
        **ai_meta,
    }
    labels = FALLBACK_LABELS.get(global_settings.report_language, FALLBACK_LABELS["en"])
    return DailyBriefing.objects.create(
        account=account,
        title=f"{labels['title']} - {title_account}",
        body_markdown=body,
        evidence=evidence,
    )


def _fallback_briefing(title_account: str, groups: dict[str, list[Finding]], language: str) -> str:
    labels = FALLBACK_LABELS.get(language, FALLBACK_LABELS["en"])
    lines = [f"# {labels['title']} - {title_account}", ""]
    lines.append(labels["read_only"])
    lines.append("")
    for severity, heading in (
        (Finding.Severity.CRITICAL, labels["critical"]),
        (Finding.Severity.WARNING, labels["warning"]),
        (Finding.Severity.INFO, labels["review"]),
    ):
        items = groups.get(severity, [])
        lines.append(f"## {heading}")
        if not items:
            lines.append(f"- {labels['no_items']}")
            lines.append("")
            continue
        for index, finding in enumerate(items[:8], start=1):
            account_name = finding.account.name
            lines.append(f"{index}. {finding.title}")
            lines.append(f"   - {labels['account']}: {account_name}")
            if finding.resource_ref:
                lines.append(f"   - {labels['resource']}: {finding.resource_ref}")
            if finding.suggested_action:
                lines.append(f"   - {labels['suggested_action']}: {finding.suggested_action}")
        lines.append("")
    return "\n".join(lines)


SEVERITY_RANK = {
    Finding.Severity.OK: 0,
    Finding.Severity.INFO: 10,
    Finding.Severity.WARNING: 20,
    Finding.Severity.CRITICAL: 30,
}


def dispatch_scan_notifications(scan_run: ScanRun) -> int:
    findings = list(
        scan_run.findings.filter(status=Finding.Status.OPEN).select_related("account")
    )
    if not findings:
        return 0

    delivered = 0
    subscriptions = NotificationSubscription.objects.select_related(
        "endpoint",
        "endpoint__user",
        "account",
    ).filter(account=scan_run.account, enabled=True, endpoint__is_active=True)
    for subscription in subscriptions:
        if not has_account_role(
            subscription.endpoint.user,
            scan_run.account,
            AccountMembership.Role.VIEWER,
        ):
            continue
        matched = [
            finding
            for finding in findings
            if SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[subscription.min_severity]
        ]
        if not matched:
            continue
        _send_webhook(subscription, scan_run, matched)
        delivered += 1
    return delivered


def _send_webhook(
    subscription: NotificationSubscription,
    scan_run: ScanRun,
    findings: list[Finding],
) -> None:
    payload = {
        "source": "infralens-ai",
        "account": {
            "id": str(scan_run.account_id),
            "name": scan_run.account.name,
            "provider": scan_run.account.provider,
            "account_ref": scan_run.account.account_ref,
        },
        "scan_run": {
            "id": str(scan_run.id),
            "status": scan_run.status,
            "finished_at": scan_run.finished_at.isoformat() if scan_run.finished_at else None,
        },
        "findings": [
            {
                "id": str(finding.id),
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "resource_ref": finding.resource_ref,
                "suggested_action": finding.suggested_action,
                "evidence": finding.evidence,
            }
            for finding in findings[:10]
        ],
    }
    summary = {
        "finding_count": len(findings),
        "min_severity": subscription.min_severity,
        "account": scan_run.account.name,
    }
    try:
        response = requests.post(
            decrypt_text(subscription.endpoint.encrypted_url),
            json=payload,
            timeout=15,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        NotificationDelivery.objects.create(
            endpoint=subscription.endpoint,
            scan_run=scan_run,
            status=NotificationDelivery.Status.FAILED,
            error_message=str(exc)[:1000],
            payload_summary=summary,
        )
        return
    NotificationDelivery.objects.create(
        endpoint=subscription.endpoint,
        scan_run=scan_run,
        status=NotificationDelivery.Status.SUCCESS,
        response_code=response.status_code,
        payload_summary=summary,
    )


def seed_demo_data() -> CloudAccount:
    account, _ = CloudAccount.objects.update_or_create(
        name="Demo AWS Production",
        provider=CloudAccount.Provider.AWS,
        account_ref="123456789012",
        defaults={
            "regions": ["ap-northeast-1", "us-east-1"],
            "encrypted_credentials": encrypt_json(
                {
                    "aws_access_key_id": "AKIADEMO000000000000",
                    "aws_secret_access_key": "demo-only",
                    "aws_session_token": "",
                }
            ),
            "credentials_hint": "AKIA...0000",
        },
    )
    Resource.objects.update_or_create(
        account=account,
        provider_id="arn:aws:lambda:ap-northeast-1:123456789012:function:daily-export",
        defaults={
            "resource_type": "aws.lambda",
            "name": "daily-export",
            "region": "ap-northeast-1",
            "metadata": {"runtime": "python3.12", "timeout": 60, "memory_size": 512},
        },
    )
    Schedule.objects.update_or_create(
        account=account,
        provider_id="arn:aws:events:ap-northeast-1:123456789012:rule/daily-export-rule",
        defaults={
            "name": "daily-export-rule",
            "region": "ap-northeast-1",
            "schedule_expression": "cron(0 17 * * ? *)",
            "state": "ENABLED",
            "target_type": "aws.lambda",
            "target_ref": "arn:aws:lambda:ap-northeast-1:123456789012:function:daily-export",
        },
    )
    Finding.objects.update_or_create(
        account=account,
        category="logs",
        title="Lambda 'daily-export' has recent timeout logs",
        resource_ref="/aws/lambda/daily-export",
        status=Finding.Status.OPEN,
        defaults={
            "severity": Finding.Severity.WARNING,
            "evidence": {
                "region": "ap-northeast-1",
                "sample_type": "timeout",
                "matched_events": 3,
            },
            "suggested_action": "Check timeout, memory, and downstream BigQuery export duration.",
        },
    )
    Finding.objects.update_or_create(
        account=account,
        category="cost",
        title="AWS cost spike in Amazon Relational Database Service",
        resource_ref="Amazon Relational Database Service",
        status=Finding.Status.OPEN,
        defaults={
            "severity": Finding.Severity.WARNING,
            "evidence": {
                "yesterday_usd": "18.40",
                "seven_day_average_usd": "6.10",
                "ratio": "3.02",
            },
            "suggested_action": "Compare scheduled report jobs and recent query volume.",
        },
    )
    Finding.objects.update_or_create(
        account=account,
        category="schedule",
        title="EventBridge rule 'staging-cleanup' has no targets",
        resource_ref="arn:aws:events:us-east-1:123456789012:rule/staging-cleanup",
        status=Finding.Status.OPEN,
        defaults={
            "severity": Finding.Severity.WARNING,
            "evidence": {"region": "us-east-1", "schedule": "rate(1 day)"},
            "suggested_action": "Attach the intended cleanup target or remove the unused schedule.",
        },
    )
    generate_daily_briefing(account, use_ai=False)
    return account
