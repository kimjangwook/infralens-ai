from django.contrib import admin

from .models import (
    AccountMembership,
    AIProvider,
    CloudAccount,
    DailyBriefing,
    Finding,
    GlobalSettings,
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


@admin.register(NotificationDelivery)
class NotificationDeliveryAdmin(admin.ModelAdmin):
    list_display = ("endpoint", "scan_run", "status", "response_code", "created_at")
    list_filter = ("status",)
