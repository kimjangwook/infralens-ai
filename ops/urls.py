from django.urls import path

from . import views

urlpatterns = [
    path("setup/", views.setup_view, name="setup"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("", views.dashboard, name="dashboard"),
    path("settings/", views.settings_view, name="settings"),
    path("settings/ai-providers/new/", views.ai_provider_create, name="ai_provider_create"),
    path(
        "settings/ai-providers/<uuid:provider_id>/edit/",
        views.ai_provider_edit,
        name="ai_provider_edit",
    ),
    path(
        "settings/ai-providers/<uuid:provider_id>/delete/",
        views.ai_provider_delete,
        name="ai_provider_delete",
    ),
    path(
        "settings/ai-providers/<uuid:provider_id>/test/",
        views.ai_provider_test,
        name="ai_provider_test",
    ),
    path("users/", views.user_list, name="users"),
    path("users/new/", views.user_create, name="user_create"),
    path("users/<int:user_id>/access/", views.user_access, name="user_access"),
    path("webhooks/", views.webhook_list, name="webhooks"),
    path("webhooks/new/", views.webhook_create, name="webhook_create"),
    path("webhooks/subscriptions/new/", views.subscription_create, name="subscription_create"),
    path("accounts/new/", views.account_create, name="account_create"),
    path("accounts/<uuid:account_id>/", views.account_detail, name="account_detail"),
    path("accounts/<uuid:account_id>/edit/", views.account_edit, name="account_edit"),
    path("accounts/<uuid:account_id>/delete/", views.account_delete, name="account_delete"),
    path("accounts/<uuid:account_id>/scan/", views.account_scan, name="account_scan"),
    path(
        "accounts/<uuid:account_id>/schedule/",
        views.account_schedule_update,
        name="account_schedule_update",
    ),
    path(
        "accounts/<uuid:account_id>/webhook-token/rotate/",
        views.account_token_regenerate,
        name="account_token_regenerate",
    ),
    path("topology/", views.topology_view, name="topology"),
    path("accounts/<uuid:account_id>/topology/", views.topology_view, name="account_topology"),
    path(
        "api/hooks/scan/<uuid:account_id>/<str:token>/",
        views.webhook_scan_trigger,
        name="webhook_scan_trigger",
    ),
    path("briefings/new/", views.briefing_create, name="briefing_create"),
    path("findings/", views.findings_table, name="findings_table"),
    path("findings/<uuid:finding_id>/", views.finding_detail, name="finding_detail"),
    path(
        "findings/<uuid:finding_id>/propose/",
        views.finding_propose_fix,
        name="finding_propose_fix",
    ),
    path("demo/seed/", views.demo_seed, name="demo_seed"),
    path("healthz/", views.healthz, name="healthz"),
]
