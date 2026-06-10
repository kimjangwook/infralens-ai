from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


def generate_webhook_token() -> str:
    return secrets.token_urlsafe(24)


class CloudAccount(models.Model):
    class Provider(models.TextChoices):
        AWS = "aws", "AWS"
        GCP = "gcp", "GCP"
        K8S = "k8s", "Kubernetes"
        AZURE = "azure", "Azure"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    provider = models.CharField(max_length=16, choices=Provider.choices)
    account_ref = models.CharField(
        max_length=180,
        blank=True,
        help_text="AWS account alias/id or GCP project id.",
    )
    regions = models.JSONField(default=list, blank=True)
    options = models.JSONField(
        default=dict,
        blank=True,
        help_text="Provider-specific options, e.g. gcp_billing_export_table.",
    )
    encrypted_credentials = models.TextField(blank=True)
    credentials_hint = models.CharField(max_length=160, blank=True)
    webhook_token = models.CharField(
        max_length=64,
        default=generate_webhook_token,
        help_text="Shared secret for the inbound scan trigger webhook.",
    )
    last_scan_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.get_provider_display()})"

    def regenerate_webhook_token(self) -> str:
        self.webhook_token = generate_webhook_token()
        self.save(update_fields=["webhook_token", "updated_at"])
        return self.webhook_token


class AccountMembership(models.Model):
    class Role(models.TextChoices):
        VIEWER = "viewer", "Viewer"
        OPERATOR = "operator", "Operator"
        ADMIN = "admin", "Admin"
        OWNER = "owner", "Owner"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="cloud_memberships",
    )
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.VIEWER)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["account__name", "user__username"]
        unique_together = [("user", "account")]

    def __str__(self) -> str:
        return f"{self.user} / {self.account} / {self.role}"


class ScanRun(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="scan_runs",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def duration_seconds(self) -> float | None:
        if not self.started_at or not self.finished_at:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def mark_running(self) -> None:
        self.status = self.Status.RUNNING
        self.started_at = timezone.now()
        self.save(update_fields=["status", "started_at"])

    def mark_success(self, summary: dict) -> None:
        self.status = self.Status.SUCCESS
        self.finished_at = timezone.now()
        self.summary = summary
        self.save(update_fields=["status", "finished_at", "summary"])
        self.account.last_scan_at = self.finished_at
        self.account.save(update_fields=["last_scan_at"])

    def mark_failed(self, message: str) -> None:
        self.status = self.Status.FAILED
        self.finished_at = timezone.now()
        self.error_message = message[:4000]
        self.save(update_fields=["status", "finished_at", "error_message"])


class ScanSchedule(models.Model):
    """In-app recurring scan plan for one cloud account.

    The ``run_scheduler`` management command (run from cron, a systemd timer,
    or the docker-compose ``scheduler`` service) executes every schedule whose
    ``next_run_at`` is due, then advances it by ``interval_minutes``.
    """

    class Interval(models.IntegerChoices):
        HOURLY = 60, "Every hour"
        EVERY_6_HOURS = 360, "Every 6 hours"
        EVERY_12_HOURS = 720, "Every 12 hours"
        DAILY = 1440, "Every day"
        WEEKLY = 10080, "Every week"

    account = models.OneToOneField(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="scan_schedule",
    )
    enabled = models.BooleanField(default=True)
    interval_minutes = models.PositiveIntegerField(
        choices=Interval.choices,
        default=Interval.DAILY,
    )
    next_run_at = models.DateTimeField(null=True, blank=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=16, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["account__name"]

    def __str__(self) -> str:
        return f"{self.account} every {self.interval_minutes}m"

    def is_due(self, now=None) -> bool:
        if not self.enabled:
            return False
        now = now or timezone.now()
        return self.next_run_at is None or self.next_run_at <= now

    def mark_ran(self, status: str, now=None) -> None:
        now = now or timezone.now()
        self.last_run_at = now
        self.last_status = status[:16]
        self.next_run_at = now + timedelta(minutes=self.interval_minutes)
        self.save(update_fields=["last_run_at", "last_status", "next_run_at", "updated_at"])


class Resource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="resources",
    )
    provider_id = models.CharField(max_length=500)
    resource_type = models.CharField(max_length=120)
    name = models.CharField(max_length=240)
    region = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    last_seen_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["resource_type", "name"]
        unique_together = [("account", "provider_id")]

    def __str__(self) -> str:
        return f"{self.resource_type}: {self.name}"


class Schedule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="schedules",
    )
    provider_id = models.CharField(max_length=500)
    name = models.CharField(max_length=240)
    region = models.CharField(max_length=80, blank=True)
    schedule_expression = models.CharField(max_length=240, blank=True)
    state = models.CharField(max_length=80, blank=True)
    target_type = models.CharField(max_length=120, blank=True)
    target_ref = models.CharField(max_length=500, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    last_seen_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["region", "name"]
        unique_together = [("account", "provider_id")]

    def __str__(self) -> str:
        return self.name


class Finding(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        WARNING = "warning", "Warning"
        INFO = "info", "Info"
        OK = "ok", "No Action"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ACKNOWLEDGED = "acknowledged", "Acknowledged"
        RESOLVED = "resolved", "Resolved"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="findings",
    )
    scan_run = models.ForeignKey(
        ScanRun,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    severity = models.CharField(max_length=16, choices=Severity.choices)
    category = models.CharField(max_length=80)
    title = models.CharField(max_length=240)
    resource_ref = models.CharField(max_length=500, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    suggested_action = models.TextField(blank=True)
    github_issue_url = models.URLField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.OPEN,
    )
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["severity", "-last_seen_at"]

    def __str__(self) -> str:
        return self.title


class RemediationProposal(models.Model):
    """An AI-drafted fix proposal for one finding.

    Proposals are text only. InfraLens never applies changes to cloud
    resources; an operator reviews the proposal and acts manually.
    """

    class Status(models.TextChoices):
        GENERATED = "generated", "AI generated"
        FALLBACK = "fallback", "Template fallback"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(
        Finding,
        on_delete=models.CASCADE,
        related_name="proposals",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="remediation_proposals",
    )
    status = models.CharField(max_length=16, choices=Status.choices)
    body_markdown = models.TextField(blank=True)
    ai_meta = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Proposal for {self.finding}"


class DailyBriefing(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="briefings",
        null=True,
        blank=True,
    )
    title = models.CharField(max_length=180)
    body_markdown = models.TextField()
    evidence = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.title


class GlobalSettings(models.Model):
    class ReportLanguage(models.TextChoices):
        EN = "en", "English"
        JA = "ja", "Japanese"
        KO = "ko", "Korean"

    report_language = models.CharField(
        max_length=8,
        choices=ReportLanguage.choices,
        default=ReportLanguage.EN,
    )
    daily_report_enabled = models.BooleanField(
        default=False,
        help_text="Generate one combined briefing across all accounts every day.",
    )
    daily_report_hour = models.PositiveSmallIntegerField(
        default=9,
        help_text="UTC hour (0-23) after which the scheduler generates the combined report.",
    )
    last_daily_report_date = models.DateField(null=True, blank=True)
    github_repo = models.CharField(
        max_length=200,
        blank=True,
        help_text="owner/repo used when creating GitHub issues from findings.",
    )
    encrypted_github_token = models.TextField(blank=True)
    github_token_hint = models.CharField(max_length=120, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Global settings"
        verbose_name_plural = "Global settings"

    def __str__(self) -> str:
        return "Global settings"

    @classmethod
    def load(cls) -> "GlobalSettings":
        settings_obj, _ = cls.objects.get_or_create(pk=1)
        return settings_obj


class AIProvider(models.Model):
    """A configurable AI backend used to generate daily briefings.

    Multiple providers can be stored. The one flagged ``is_default`` (and active)
    is used for briefing generation. API keys are encrypted at rest.
    """

    class Provider(models.TextChoices):
        OPENAI = "openai", "OpenAI"
        ANTHROPIC = "anthropic", "Anthropic (Claude)"
        GOOGLE = "google", "Google (Gemini)"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    provider = models.CharField(max_length=24, choices=Provider.choices)
    model = models.CharField(
        max_length=120,
        help_text="Model id, e.g. gpt-5.5, claude-opus-4-8, gemini-3.5-flash.",
    )
    encrypted_api_key = models.TextField(blank=True)
    api_key_hint = models.CharField(max_length=120, blank=True)
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-is_default", "name"]
        verbose_name = "AI provider"
        verbose_name_plural = "AI providers"

    def __str__(self) -> str:
        return f"{self.name} ({self.get_provider_display()})"

    def save(self, *args, **kwargs) -> None:
        super().save(*args, **kwargs)
        # Keep a single default provider. Done after save so the new row exists.
        if self.is_default:
            AIProvider.objects.exclude(pk=self.pk).filter(is_default=True).update(
                is_default=False
            )

    @classmethod
    def get_default(cls) -> "AIProvider | None":
        provider = cls.objects.filter(is_active=True, is_default=True).first()
        if provider:
            return provider
        return cls.objects.filter(is_active=True).first()


class WebhookEndpoint(models.Model):
    class Provider(models.TextChoices):
        GENERIC = "generic", "Generic webhook"
        SLACK = "slack", "Slack incoming webhook"
        NOTION = "notion", "Notion page export"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="webhook_endpoints",
    )
    name = models.CharField(max_length=120)
    provider = models.CharField(
        max_length=24,
        choices=Provider.choices,
        default=Provider.GENERIC,
    )
    encrypted_url = models.TextField()
    url_hint = models.CharField(max_length=180, blank=True)
    config = models.JSONField(
        default=dict,
        blank=True,
        help_text="Provider-specific options, e.g. notion_parent_page_id.",
    )
    receive_daily_report = models.BooleanField(
        default=False,
        help_text="Also send the combined daily report to this endpoint.",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.user})"


class NotificationSubscription(models.Model):
    endpoint = models.ForeignKey(
        WebhookEndpoint,
        on_delete=models.CASCADE,
        related_name="subscriptions",
    )
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="notification_subscriptions",
    )
    min_severity = models.CharField(
        max_length=16,
        choices=Finding.Severity.choices,
        default=Finding.Severity.WARNING,
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["account__name", "endpoint__name"]
        unique_together = [("endpoint", "account")]

    def __str__(self) -> str:
        return f"{self.endpoint} -> {self.account}"


class BackgroundJob(models.Model):
    """Minimal DB-backed job queue so long scans can run off the request path.

    The ``run_worker`` management command claims queued jobs with an atomic
    UPDATE, so multiple workers can run side by side without double execution.
    """

    class Kind(models.TextChoices):
        SCAN = "scan", "Account scan"
        DAILY_REPORT = "daily_report", "Combined daily report"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        DONE = "done", "Done"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=24, choices=Kind.choices)
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="background_jobs",
        null=True,
        blank=True,
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.kind} ({self.status})"


class CustomRule(models.Model):
    """User-defined detector evaluated against the inventory after each scan.

    Rules match a field on scanned resources or schedules with a simple
    operator; matches become findings in the ``custom`` category.
    """

    class Target(models.TextChoices):
        RESOURCE = "resource", "Resource"
        SCHEDULE = "schedule", "Schedule"

    class Operator(models.TextChoices):
        EQUALS = "equals", "Equals"
        NOT_EQUALS = "not_equals", "Does not equal"
        CONTAINS = "contains", "Contains"
        NOT_CONTAINS = "not_contains", "Does not contain"
        GT = "gt", "Greater than (numeric)"
        LT = "lt", "Less than (numeric)"
        REGEX = "regex", "Matches regex"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    account = models.ForeignKey(
        CloudAccount,
        on_delete=models.CASCADE,
        related_name="custom_rules",
        null=True,
        blank=True,
        help_text="Leave empty to apply the rule to every account.",
    )
    target = models.CharField(max_length=16, choices=Target.choices)
    field_path = models.CharField(
        max_length=160,
        help_text="Field to inspect, e.g. name, region, state, metadata.timeout.",
    )
    operator = models.CharField(max_length=16, choices=Operator.choices)
    value = models.CharField(max_length=240)
    severity = models.CharField(
        max_length=16,
        choices=Finding.Severity.choices,
        default=Finding.Severity.WARNING,
    )
    suggested_action = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class NotificationDelivery(models.Model):
    class Status(models.TextChoices):
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    endpoint = models.ForeignKey(
        WebhookEndpoint,
        on_delete=models.CASCADE,
        related_name="deliveries",
    )
    scan_run = models.ForeignKey(
        ScanRun,
        on_delete=models.CASCADE,
        related_name="notification_deliveries",
    )
    status = models.CharField(max_length=16, choices=Status.choices)
    response_code = models.PositiveIntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    payload_summary = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
