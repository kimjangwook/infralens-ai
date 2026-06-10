from django.contrib import admin

from .models import (
    AccountMembership,
    AIProvider,
    CloudAccount,
    DailyBriefing,
    Finding,
    GlobalSettings,
    AuditLog,
    BackgroundJob,
    CustomRule,
    Invitation,
    UsageRecord,
    NotificationDelivery,
    NotificationSubscription,
    RemediationProposal,
    Resource,
    ScanRun,
    ScanSchedule,
    Schedule,
    WebhookEndpoint,
)


@admin.register(CloudAccount)
class CloudAccountAdmin(admin.ModelAdmin):
    list_display = ("name", "provider", "account_ref", "last_scan_at", "created_at")
    list_filter = ("provider",)
    search_fields = ("name", "account_ref")
    readonly_fields = ("encrypted_credentials", "created_at", "updated_at")


@admin.register(AccountMembership)
class AccountMembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "account", "role", "updated_at")
    list_filter = ("role", "account__provider")
    search_fields = ("user__username", "account__name")


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ("account", "status", "started_at", "finished_at")
    list_filter = ("status", "account__provider")
    search_fields = ("account__name", "error_message")


@admin.register(Resource)
class ResourceAdmin(admin.ModelAdmin):
    list_display = ("name", "resource_type", "account", "region", "last_seen_at")
    list_filter = ("resource_type", "account__provider", "region")
    search_fields = ("name", "provider_id")


@admin.register(Schedule)
class ScheduleAdmin(admin.ModelAdmin):
    list_display = ("name", "account", "region", "state", "target_type")
    list_filter = ("account__provider", "state", "region")
    search_fields = ("name", "target_ref", "schedule_expression")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "category", "account", "status", "last_seen_at")
    list_filter = ("severity", "category", "status", "account__provider")
    search_fields = ("title", "resource_ref")


@admin.register(DailyBriefing)
class DailyBriefingAdmin(admin.ModelAdmin):
    list_display = ("title", "account", "created_at")
    search_fields = ("title", "body_markdown")


@admin.register(GlobalSettings)
class GlobalSettingsAdmin(admin.ModelAdmin):
    list_display = ("report_language", "updated_at")


@admin.register(AIProvider)
class AIProviderAdmin(admin.ModelAdmin):
    list_display = ("name", "provider", "model", "is_default", "is_active", "updated_at")
    list_filter = ("provider", "is_active", "is_default")
    search_fields = ("name", "model")
    readonly_fields = ("encrypted_api_key", "api_key_hint", "created_at", "updated_at")


@admin.register(WebhookEndpoint)
class WebhookEndpointAdmin(admin.ModelAdmin):
    list_display = ("name", "user", "provider", "url_hint", "is_active", "updated_at")
    list_filter = ("provider", "is_active")
    search_fields = ("name", "user__username", "url_hint")
    readonly_fields = ("encrypted_url",)


@admin.register(NotificationSubscription)
class NotificationSubscriptionAdmin(admin.ModelAdmin):
    list_display = ("endpoint", "account", "min_severity", "enabled", "updated_at")
    list_filter = ("min_severity", "enabled")


@admin.register(ScanSchedule)
class ScanScheduleAdmin(admin.ModelAdmin):
    list_display = ("account", "enabled", "interval_minutes", "next_run_at", "last_run_at", "last_status")
    list_filter = ("enabled", "interval_minutes")
    search_fields = ("account__name",)


@admin.register(RemediationProposal)
class RemediationProposalAdmin(admin.ModelAdmin):
    list_display = ("finding", "status", "requested_by", "created_at")
    list_filter = ("status",)
    search_fields = ("finding__title",)


@admin.register(BackgroundJob)
class BackgroundJobAdmin(admin.ModelAdmin):
    list_display = ("kind", "account", "status", "created_at", "finished_at")
    list_filter = ("kind", "status")


@admin.register(CustomRule)
class CustomRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "account", "target", "field_path", "operator", "severity", "enabled")
    list_filter = ("target", "operator", "severity", "enabled")
    search_fields = ("name", "field_path", "value")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "user", "target", "created_at")
    list_filter = ("action",)
    search_fields = ("action", "target", "user__username")
    readonly_fields = ("user", "action", "target", "metadata", "created_at")


@admin.register(UsageRecord)
class UsageRecordAdmin(admin.ModelAdmin):
    list_display = ("date", "kind", "count")
    list_filter = ("kind",)


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ("note", "invited_by", "expires_at", "accepted_by", "created_at")
    readonly_fields = ("token",)


@admin.register(NotificationDelivery)
class NotificationDeliveryAdmin(admin.ModelAdmin):
    list_display = ("endpoint", "scan_run", "status", "response_code", "created_at")
    list_filter = ("status",)
