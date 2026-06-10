from __future__ import annotations

from collections import defaultdict
from typing import Iterable

import requests
from django.db.models import Count, Q

from django.utils import timezone

from .ai import generate_ai_insight, generate_remediation_text
from .authz import has_account_role
from .crypto import decrypt_text, encrypt_json
from .models import (
    AccountMembership,
    BackgroundJob,
    CloudAccount,
    DailyBriefing,
    Finding,
    GlobalSettings,
    NotificationDelivery,
    NotificationSubscription,
    RemediationProposal,
    Resource,
    Schedule,
    ScanRun,
    WebhookEndpoint,
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


def run_scan_pipeline(account: CloudAccount, *, use_ai: bool = True) -> ScanRun:
    """Scan one account and, on success, refresh the briefing and notify.

    Single entry point shared by the dashboard button, the management
    commands, the in-app scheduler, and the inbound trigger webhook so every
    path produces the same artifacts.
    """
    from .billing import record_usage
    from .models import UsageRecord
    from .scanners import run_scan

    scan_run = run_scan(account)
    record_usage(UsageRecord.Kind.SCAN)
    if scan_run.status == ScanRun.Status.SUCCESS:
        generate_daily_briefing(account, use_ai=use_ai)
        dispatch_scan_notifications(scan_run)
    return scan_run


def enqueue_scan(account: CloudAccount) -> BackgroundJob:
    """Queue a scan for the background worker instead of running it inline."""
    return BackgroundJob.objects.create(
        kind=BackgroundJob.Kind.SCAN,
        account=account,
    )


def claim_next_job() -> BackgroundJob | None:
    """Atomically claim one queued job; safe with multiple workers."""
    job = BackgroundJob.objects.filter(status=BackgroundJob.Status.QUEUED).first()
    if job is None:
        return None
    claimed = BackgroundJob.objects.filter(
        pk=job.pk, status=BackgroundJob.Status.QUEUED
    ).update(status=BackgroundJob.Status.RUNNING, started_at=timezone.now())
    if not claimed:
        return None
    job.refresh_from_db()
    return job


def process_job(job: BackgroundJob) -> None:
    try:
        if job.kind == BackgroundJob.Kind.SCAN and job.account:
            scan_run = run_scan_pipeline(job.account)
            job.result = {"scan_run": str(scan_run.id), "status": scan_run.status}
            if scan_run.status == ScanRun.Status.FAILED:
                raise RuntimeError(scan_run.error_message or "scan failed")
        elif job.kind == BackgroundJob.Kind.DAILY_REPORT:
            briefing = generate_daily_briefing(None)
            dispatch_daily_report(briefing)
            job.result = {"briefing": str(briefing.id)}
        else:
            raise ValueError(f"Unsupported job kind: {job.kind}")
    except Exception as exc:  # noqa: BLE001 - worker must record any failure.
        job.status = BackgroundJob.Status.FAILED
        job.error_message = str(exc)[:2000]
    else:
        job.status = BackgroundJob.Status.DONE
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "result", "error_message", "finished_at"])


def maybe_generate_daily_report(now=None) -> DailyBriefing | None:
    """Generate the combined all-accounts report once per day when enabled."""
    now = now or timezone.now()
    settings_obj = get_global_settings()
    if not settings_obj.daily_report_enabled:
        return None
    if now.hour < settings_obj.daily_report_hour:
        return None
    if settings_obj.last_daily_report_date == now.date():
        return None
    briefing = generate_daily_briefing(None)
    dispatch_daily_report(briefing)
    settings_obj.last_daily_report_date = now.date()
    settings_obj.save(update_fields=["last_daily_report_date", "updated_at"])
    return briefing


def dispatch_daily_report(briefing: DailyBriefing) -> int:
    endpoints = WebhookEndpoint.objects.filter(is_active=True, receive_daily_report=True)
    delivered = 0
    for endpoint in endpoints:
        if _send_briefing(endpoint, briefing):
            delivered += 1
    return delivered


def _send_briefing(endpoint: WebhookEndpoint, briefing: DailyBriefing) -> bool:
    secret = decrypt_text(endpoint.encrypted_url)
    try:
        if endpoint.provider == WebhookEndpoint.Provider.SLACK:
            response = requests.post(
                secret,
                json={"text": f"{briefing.title}\n\n{briefing.body_markdown[:3500]}"},
                timeout=15,
            )
        elif endpoint.provider == WebhookEndpoint.Provider.NOTION:
            children = [
                {
                    "object": "block",
                    "type": "paragraph",
                    "paragraph": {
                        "rich_text": [
                            {"type": "text", "text": {"content": chunk[:1900]}}
                        ]
                    },
                }
                for chunk in briefing.body_markdown.split("\n\n")[:40]
                if chunk.strip()
            ]
            response = requests.post(
                "https://api.notion.com/v1/pages",
                headers={
                    "Authorization": f"Bearer {secret}",
                    "Notion-Version": "2022-06-28",
                },
                json={
                    "parent": {
                        "page_id": (endpoint.config or {}).get("notion_parent_page_id", "")
                    },
                    "properties": {
                        "title": {
                            "title": [
                                {"type": "text", "text": {"content": briefing.title[:200]}}
                            ]
                        }
                    },
                    "children": children,
                },
                timeout=15,
            )
        else:
            response = requests.post(
                secret,
                json={
                    "source": "infralens-ai",
                    "type": "daily_report",
                    "title": briefing.title,
                    "body_markdown": briefing.body_markdown,
                    "evidence": briefing.evidence,
                },
                timeout=15,
            )
        response.raise_for_status()
    except requests.RequestException:
        return False
    return True


def create_github_issue(finding: Finding) -> tuple[bool, str]:
    """Open a GitHub issue for one finding. Returns (ok, message-or-url)."""
    settings_obj = get_global_settings()
    repo = settings_obj.github_repo.strip()
    token = decrypt_text(settings_obj.encrypted_github_token)
    if not repo or not token:
        return False, "Configure the GitHub repository and token in Settings first."

    body_lines = [
        f"**Severity:** {finding.get_severity_display()}",
        f"**Account:** {finding.account.name} ({finding.account.get_provider_display()})",
        f"**Category:** {finding.category}",
    ]
    if finding.resource_ref:
        body_lines.append(f"**Resource:** `{finding.resource_ref}`")
    if finding.suggested_action:
        body_lines.append(f"\n**Suggested action:** {finding.suggested_action}")
    if finding.evidence:
        body_lines.append("\n**Evidence:**\n```json")
        body_lines.append(str(finding.evidence)[:2000])
        body_lines.append("```")
    body_lines.append("\n_Opened by InfraLens AI. Proposals are suggestions only._")

    try:
        response = requests.post(
            f"https://api.github.com/repos/{repo}/issues",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"title": f"[InfraLens] {finding.title}"[:250], "body": "\n".join(body_lines)},
            timeout=15,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        return False, f"GitHub request failed: {str(exc)[:200]}"

    issue_url = response.json().get("html_url", "")
    if issue_url:
        finding.github_issue_url = issue_url
        finding.save(update_fields=["github_issue_url"])
    return True, issue_url or "Issue created."


REMEDIATION_FALLBACK_LABELS = {
    GlobalSettings.ReportLanguage.EN: {
        "title": "Remediation proposal",
        "note": (
            "AI was unavailable, so this is a deterministic template built from "
            "the stored evidence. InfraLens never applies changes automatically."
        ),
        "finding": "Finding",
        "evidence": "Evidence",
        "steps": "Proposed next steps",
        "rollback": "Before applying",
        "rollback_note": (
            "Review each step with your team and export the current configuration "
            "first so you can roll back."
        ),
    },
    GlobalSettings.ReportLanguage.JA: {
        "title": "修正提案",
        "note": (
            "AI が利用できないため、保存された証拠に基づくテンプレートを表示しています。"
            "InfraLens が自動で変更を適用することはありません。"
        ),
        "finding": "検出項目",
        "evidence": "証拠",
        "steps": "推奨される次のステップ",
        "rollback": "適用前の確認",
        "rollback_note": "各手順をチームで確認し、ロールバックできるよう現在の設定を先に保存してください。",
    },
    GlobalSettings.ReportLanguage.KO: {
        "title": "수정 제안",
        "note": (
            "AI를 사용할 수 없어 저장된 증거 기반의 템플릿을 표시합니다. "
            "InfraLens는 변경을 자동으로 적용하지 않습니다."
        ),
        "finding": "발견 항목",
        "evidence": "증거",
        "steps": "제안되는 다음 단계",
        "rollback": "적용 전 확인",
        "rollback_note": "각 단계를 팀과 검토하고, 롤백할 수 있도록 현재 설정을 먼저 백업하세요.",
    },
}


def create_remediation_proposal(
    finding: Finding,
    requested_by=None,
) -> RemediationProposal:
    """One-button fix proposal: AI draft with a deterministic fallback."""
    global_settings = get_global_settings()
    body, meta = generate_remediation_text(
        finding=finding,
        report_language=global_settings.report_language,
        context=_related_infrastructure(finding),
    )
    status = RemediationProposal.Status.GENERATED
    if body is None:
        body = _fallback_remediation(finding, global_settings.report_language)
        status = RemediationProposal.Status.FALLBACK
    else:
        from .billing import record_usage
        from .models import UsageRecord

        record_usage(UsageRecord.Kind.AI_CALL)
    return RemediationProposal.objects.create(
        finding=finding,
        requested_by=requested_by,
        status=status,
        body_markdown=body,
        ai_meta={"report_language": global_settings.report_language, **meta},
    )


def _related_infrastructure(finding: Finding) -> dict:
    """Topology context handed to the AI so proposals see neighbors, not just
    the single finding."""
    ref = finding.resource_ref
    schedules = finding.account.schedules.all()
    resources = finding.account.resources.all()
    related_schedules = [
        {
            "name": schedule.name,
            "expression": schedule.schedule_expression,
            "state": schedule.state,
            "target_ref": schedule.target_ref,
        }
        for schedule in schedules
        if ref and (ref in schedule.target_ref or schedule.target_ref in ref or schedule.name in ref)
    ][:5]
    related_resources = [
        {
            "name": resource.name,
            "type": resource.resource_type,
            "region": resource.region,
            "metadata": resource.metadata,
        }
        for resource in resources
        if ref and (ref in resource.provider_id or resource.provider_id in ref or resource.name in ref)
    ][:5]
    return {
        "related_schedules": related_schedules,
        "related_resources": related_resources,
        "account_totals": {
            "resources": resources.count(),
            "schedules": schedules.count(),
        },
    }


def _fallback_remediation(finding: Finding, language: str) -> str:
    labels = REMEDIATION_FALLBACK_LABELS.get(
        language, REMEDIATION_FALLBACK_LABELS[GlobalSettings.ReportLanguage.EN]
    )
    lines = [f"# {labels['title']}: {finding.title}", "", labels["note"], ""]
    lines.append(f"## {labels['finding']}")
    lines.append(f"- {finding.get_severity_display()} / {finding.category}")
    if finding.resource_ref:
        lines.append(f"- {finding.resource_ref}")
    lines.append("")
    lines.append(f"## {labels['evidence']}")
    for key, value in (finding.evidence or {}).items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append(f"## {labels['steps']}")
    if finding.suggested_action:
        lines.append(f"1. {finding.suggested_action}")
    else:
        lines.append("1. -")
    lines.append("")
    lines.append(f"## {labels['rollback']}")
    lines.append(labels["rollback_note"])
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


def _generic_payload(scan_run: ScanRun, findings: list[Finding]) -> dict:
    return {
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


def _slack_payload(scan_run: ScanRun, findings: list[Finding]) -> dict:
    """Slack incoming-webhook message with one section per finding."""
    header = (
        f"InfraLens: {len(findings)} finding(s) for {scan_run.account.name} "
        f"({scan_run.account.get_provider_display()})"
    )
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": header[:150]}},
    ]
    for finding in findings[:10]:
        text = f"*{finding.severity.upper()}* {finding.title}"
        if finding.suggested_action:
            text += f"\n_{finding.suggested_action}_"
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}
        )
    return {"text": header, "blocks": blocks}


def _notion_payload(endpoint: WebhookEndpoint, scan_run: ScanRun, findings: list[Finding]) -> dict:
    """Notion create-page request appending findings under the configured parent."""
    title = f"InfraLens scan - {scan_run.account.name}"
    children = [
        {
            "object": "block",
            "type": "bulleted_list_item",
            "bulleted_list_item": {
                "rich_text": [
                    {
                        "type": "text",
                        "text": {
                            "content": f"[{finding.severity}] {finding.title}"[:1900]
                        },
                    }
                ]
            },
        }
        for finding in findings[:20]
    ]
    return {
        "parent": {"page_id": (endpoint.config or {}).get("notion_parent_page_id", "")},
        "properties": {
            "title": {"title": [{"type": "text", "text": {"content": title[:200]}}]}
        },
        "children": children,
    }


def _send_webhook(
    subscription: NotificationSubscription,
    scan_run: ScanRun,
    findings: list[Finding],
) -> None:
    endpoint = subscription.endpoint
    secret = decrypt_text(endpoint.encrypted_url)
    summary = {
        "finding_count": len(findings),
        "min_severity": subscription.min_severity,
        "account": scan_run.account.name,
        "provider": endpoint.provider,
    }
    try:
        if endpoint.provider == WebhookEndpoint.Provider.SLACK:
            response = requests.post(
                secret, json=_slack_payload(scan_run, findings), timeout=15
            )
        elif endpoint.provider == WebhookEndpoint.Provider.NOTION:
            response = requests.post(
                "https://api.notion.com/v1/pages",
                headers={
                    "Authorization": f"Bearer {secret}",
                    "Notion-Version": "2022-06-28",
                },
                json=_notion_payload(endpoint, scan_run, findings),
                timeout=15,
            )
        else:
            response = requests.post(
                secret, json=_generic_payload(scan_run, findings), timeout=15
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
