from __future__ import annotations

from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from .authz import (
    accessible_accounts,
    global_admin_required,
    has_account_role,
    product_login_required,
    users_exist,
)
from .forms import (
    AI_MODEL_SUGGESTIONS,
    AIProviderForm,
    CloudAccountForm,
    GlobalSettingsForm,
    NotificationSubscriptionForm,
    ProductLoginForm,
    ProductUserCreationForm,
    ScanScheduleForm,
    SetupForm,
    UserAccessForm,
    WebhookEndpointForm,
)
from .models import (
    AccountMembership,
    AIProvider,
    CloudAccount,
    DailyBriefing,
    Finding,
    GlobalSettings,
    NotificationDelivery,
    NotificationSubscription,
    ScanSchedule,
    WebhookEndpoint,
)
from .ai import verify_ai_provider
from .services import (
    account_stats,
    create_github_issue,
    create_remediation_proposal,
    dashboard_stats,
    enqueue_scan,
    finding_summary_by_category,
    generate_daily_briefing,
    get_global_settings,
    run_scan_pipeline,
    seed_demo_data,
)
from .topology import build_topology, render_mermaid, topology_insights


@require_http_methods(["GET", "POST"])
def setup_view(request: HttpRequest) -> HttpResponse:
    if users_exist():
        return redirect("dashboard")
    if request.method == "POST":
        form = SetupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_staff = True
            user.is_superuser = True
            user.save()
            login(request, user)
            messages.success(request, "Owner account created.")
            return redirect("dashboard")
    else:
        form = SetupForm()
    return render(request, "ops/setup.html", {"form": form})


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if not users_exist():
        return redirect("setup")
    if request.user.is_authenticated:
        return redirect("dashboard")
    if request.method == "POST":
        form = ProductLoginForm(request, data=request.POST)
        if form.is_valid():
            login(request, form.get_user())
            return redirect(request.GET.get("next") or "dashboard")
    else:
        form = ProductLoginForm()
    return render(request, "ops/login.html", {"form": form})


@require_POST
def logout_view(request: HttpRequest) -> HttpResponse:
    logout(request)
    return redirect("login")


@product_login_required
@require_GET
def dashboard(request: HttpRequest) -> HttpResponse:
    accounts = accessible_accounts(request.user)
    latest_findings = Finding.objects.select_related("account").filter(
        account__in=accounts,
        status=Finding.Status.OPEN,
    )[:12]
    latest_briefing = DailyBriefing.objects.select_related("account").filter(
        account__in=accounts
    ).first()
    return render(
        request,
        "ops/dashboard.html",
        {
            "stats": dashboard_stats(accounts),
            "accounts": accounts,
            "latest_findings": latest_findings,
            "latest_briefing": latest_briefing,
            "category_summary": finding_summary_by_category(accounts),
            "global_settings": get_global_settings(),
        },
    )


@global_admin_required
def account_create(request: HttpRequest) -> HttpResponse:
    from .billing import can_add_account, plan_limits

    if not can_add_account():
        messages.error(
            request,
            f"Your plan allows {plan_limits()['accounts']} cloud account(s). "
            "Upgrade the plan or remove an account first.",
        )
        return redirect("dashboard")
    if request.method == "POST":
        form = CloudAccountForm(request.POST)
        if form.is_valid():
            account = form.save()
            AccountMembership.objects.update_or_create(
                user=request.user,
                account=account,
                defaults={"role": AccountMembership.Role.OWNER},
            )
            messages.success(request, f"{account.name} was added.")
            return redirect("account_detail", account_id=account.id)
    else:
        form = CloudAccountForm()
    return render(request, "ops/account_form.html", {"form": form})


@product_login_required
@require_http_methods(["GET", "POST"])
def account_edit(request: HttpRequest, account_id) -> HttpResponse:
    account = get_object_or_404(accessible_accounts(request.user), id=account_id)
    if not has_account_role(request.user, account, AccountMembership.Role.ADMIN):
        messages.error(request, "You need account admin access to edit this account.")
        return redirect("account_detail", account_id=account.id)
    if request.method == "POST":
        form = CloudAccountForm(request.POST, instance=account)
        if form.is_valid():
            form.save()
            messages.success(request, f"{account.name} was updated.")
            return redirect("account_detail", account_id=account.id)
    else:
        form = CloudAccountForm(instance=account)
    return render(
        request,
        "ops/account_form.html",
        {"form": form, "account": account, "is_edit": True},
    )


@product_login_required
@require_POST
def account_delete(request: HttpRequest, account_id) -> HttpResponse:
    account = get_object_or_404(accessible_accounts(request.user), id=account_id)
    if not has_account_role(request.user, account, AccountMembership.Role.OWNER):
        messages.error(request, "You need account owner access to delete this account.")
        return redirect("account_detail", account_id=account.id)
    name = account.name
    account.delete()
    messages.success(request, f"{name} was deleted.")
    return redirect("dashboard")


@global_admin_required
def settings_view(request: HttpRequest) -> HttpResponse:
    settings_obj = GlobalSettings.load()
    if request.method == "POST":
        form = GlobalSettingsForm(request.POST, instance=settings_obj)
        if form.is_valid():
            form.save()
            messages.success(request, "Settings were saved.")
            return redirect("settings")
    else:
        form = GlobalSettingsForm(instance=settings_obj)
    from .billing import effective_plan, plan_limits, usage_this_month, usage_today
    from .models import UsageRecord

    return render(
        request,
        "ops/settings.html",
        {
            "form": form,
            "settings_obj": settings_obj,
            "ai_providers": AIProvider.objects.all(),
            "plan": effective_plan(),
            "limits": plan_limits(),
            "account_count": CloudAccount.objects.count(),
            "user_count": get_user_model().objects.count(),
            "ai_used_today": usage_today(UsageRecord.Kind.AI_CALL),
            "usage_month": usage_this_month(),
        },
    )


@global_admin_required
@require_http_methods(["GET", "POST"])
def ai_provider_create(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = AIProviderForm(request.POST)
        if form.is_valid():
            provider = form.save()
            messages.success(request, f"AI provider {provider.name} was added.")
            return redirect("settings")
    else:
        form = AIProviderForm()
    return render(
        request,
        "ops/ai_provider_form.html",
        {"form": form, "is_edit": False, "model_suggestions": AI_MODEL_SUGGESTIONS},
    )


@global_admin_required
@require_http_methods(["GET", "POST"])
def ai_provider_edit(request: HttpRequest, provider_id) -> HttpResponse:
    provider = get_object_or_404(AIProvider, id=provider_id)
    if request.method == "POST":
        form = AIProviderForm(request.POST, instance=provider)
        if form.is_valid():
            form.save()
            messages.success(request, f"AI provider {provider.name} was updated.")
            return redirect("settings")
    else:
        form = AIProviderForm(instance=provider)
    return render(
        request,
        "ops/ai_provider_form.html",
        {
            "form": form,
            "is_edit": True,
            "provider": provider,
            "model_suggestions": AI_MODEL_SUGGESTIONS,
        },
    )


@global_admin_required
@require_POST
def ai_provider_delete(request: HttpRequest, provider_id) -> HttpResponse:
    provider = get_object_or_404(AIProvider, id=provider_id)
    name = provider.name
    provider.delete()
    messages.success(request, f"AI provider {name} was deleted.")
    return redirect("settings")


@global_admin_required
@require_POST
def ai_provider_test(request: HttpRequest, provider_id) -> HttpResponse:
    provider = get_object_or_404(AIProvider, id=provider_id)
    ok, message = verify_ai_provider(provider)
    if ok:
        messages.success(request, message)
    else:
        messages.error(request, f"{provider.name}: {message}")
    return redirect("settings")


@product_login_required
@require_GET
def account_detail(request: HttpRequest, account_id) -> HttpResponse:
    account = get_object_or_404(accessible_accounts(request.user), id=account_id)
    can_edit = has_account_role(request.user, account, AccountMembership.Role.ADMIN)
    scan_schedule = ScanSchedule.objects.filter(account=account).first()
    trigger_url = request.build_absolute_uri(
        reverse("webhook_scan_trigger", args=[account.id, account.webhook_token])
    )
    return render(
        request,
        "ops/account_detail.html",
        {
            "account": account,
            "stats": account_stats(account),
            "schedules": account.schedules.all()[:40],
            "resources": account.resources.all()[:40],
            "findings": account.findings.filter(status=Finding.Status.OPEN)[:40],
            "scan_runs": account.scan_runs.all()[:10],
            "briefing": account.briefings.first(),
            "can_edit": can_edit,
            "can_delete": has_account_role(request.user, account, AccountMembership.Role.OWNER),
            "scan_schedule": scan_schedule,
            "schedule_form": ScanScheduleForm(instance=scan_schedule),
            "trigger_url": trigger_url if can_edit else "",
        },
    )


@product_login_required
@require_POST
def account_scan(request: HttpRequest, account_id) -> HttpResponse:
    account = get_object_or_404(accessible_accounts(request.user), id=account_id)
    if not has_account_role(request.user, account, AccountMembership.Role.OPERATOR):
        messages.error(request, "You need operator access to run scans.")
        return redirect("account_detail", account_id=account.id)
    from django.conf import settings as django_settings

    if django_settings.ASYNC_SCANS:
        job = enqueue_scan(account)
        messages.success(
            request,
            f"Scan queued for {account.name} (job {job.id}). The worker will pick it up.",
        )
        return redirect("account_detail", account_id=account.id)
    scan_run = run_scan_pipeline(account)
    if scan_run.status == scan_run.Status.SUCCESS:
        messages.success(request, f"Scan finished for {account.name}.")
    else:
        messages.error(request, f"Scan failed for {account.name}: {scan_run.error_message}")
    return redirect("account_detail", account_id=account.id)


@product_login_required
@require_GET
def resource_detail(request: HttpRequest, resource_id) -> HttpResponse:
    from django.db.models import Q

    from .models import RemediationProposal, Resource

    resource = get_object_or_404(
        Resource.objects.select_related("account").filter(
            account__in=accessible_accounts(request.user)
        ),
        id=resource_id,
    )
    related_findings = Finding.objects.filter(account=resource.account).filter(
        Q(resource_ref__icontains=resource.provider_id)
        | Q(resource_ref__icontains=resource.name)
    )[:40]
    proposals = RemediationProposal.objects.select_related("finding").filter(
        finding__in=related_findings
    )[:10]
    inbound_schedules = resource.account.schedules.filter(
        Q(target_ref=resource.provider_id) | Q(target_ref__icontains=resource.name)
    )[:20]
    return render(
        request,
        "ops/resource_detail.html",
        {
            "resource": resource,
            "findings": related_findings,
            "proposals": proposals,
            "inbound_schedules": inbound_schedules,
        },
    )


@product_login_required
@require_GET
def topology_view(request: HttpRequest, account_id=None) -> HttpResponse:
    accounts = accessible_accounts(request.user)
    account = None
    if account_id:
        account = get_object_or_404(accounts, id=account_id)
        accounts = accounts.filter(id=account.id)
    graph = build_topology(accounts)
    return render(
        request,
        "ops/topology.html",
        {
            "account": account,
            "accounts": accessible_accounts(request.user),
            "graph": graph,
            "mermaid_source": render_mermaid(graph),
            "insights": topology_insights(graph),
        },
    )


@product_login_required
@require_POST
def account_schedule_update(request: HttpRequest, account_id) -> HttpResponse:
    account = get_object_or_404(accessible_accounts(request.user), id=account_id)
    if not has_account_role(request.user, account, AccountMembership.Role.ADMIN):
        messages.error(request, "You need account admin access to change the scan schedule.")
        return redirect("account_detail", account_id=account.id)
    schedule, _ = ScanSchedule.objects.get_or_create(account=account)
    form = ScanScheduleForm(request.POST, instance=schedule)
    if form.is_valid():
        schedule = form.save(commit=False)
        # A newly enabled or re-tuned schedule becomes due immediately; the
        # scheduler advances it by the interval after each run.
        if schedule.enabled:
            schedule.next_run_at = timezone.now()
        schedule.save()
        messages.success(request, f"Scan schedule updated for {account.name}.")
    else:
        messages.error(request, "Could not save the scan schedule.")
    return redirect("account_detail", account_id=account.id)


@product_login_required
@require_POST
def account_token_regenerate(request: HttpRequest, account_id) -> HttpResponse:
    account = get_object_or_404(accessible_accounts(request.user), id=account_id)
    if not has_account_role(request.user, account, AccountMembership.Role.ADMIN):
        messages.error(request, "You need account admin access to rotate the webhook token.")
        return redirect("account_detail", account_id=account.id)
    account.regenerate_webhook_token()
    messages.success(request, "Webhook trigger URL was rotated. Update any callers.")
    return redirect("account_detail", account_id=account.id)


@csrf_exempt
@require_POST
def webhook_scan_trigger(request: HttpRequest, account_id, token: str) -> JsonResponse:
    """Inbound webhook: lets CI/CD or external cron trigger a scan remotely.

    Authenticated by the per-account token in the URL path, not by a session,
    so it is safe to call from headless systems.
    """
    try:
        account = CloudAccount.objects.get(id=account_id)
    except CloudAccount.DoesNotExist:
        return JsonResponse({"error": "unknown account"}, status=404)
    if not constant_time_compare(token, account.webhook_token):
        return JsonResponse({"error": "invalid token"}, status=403)

    from django.conf import settings as django_settings

    if django_settings.ASYNC_SCANS:
        job = enqueue_scan(account)
        return JsonResponse({"job": str(job.id), "status": "queued"}, status=202)

    scan_run = run_scan_pipeline(account)
    payload = {
        "scan_run": str(scan_run.id),
        "status": scan_run.status,
        "summary": scan_run.summary,
    }
    if scan_run.status == scan_run.Status.FAILED:
        payload["error"] = scan_run.error_message
        return JsonResponse(payload, status=502)
    return JsonResponse(payload)


@product_login_required
@require_POST
def finding_propose_fix(request: HttpRequest, finding_id) -> HttpResponse:
    finding = get_object_or_404(
        Finding.objects.select_related("account").filter(
            account__in=accessible_accounts(request.user)
        ),
        id=finding_id,
    )
    if not has_account_role(request.user, finding.account, AccountMembership.Role.OPERATOR):
        messages.error(request, "You need operator access to request fix proposals.")
        return redirect("finding_detail", finding_id=finding.id)
    from .billing import can_generate_proposal_today, plan_limits

    if not can_generate_proposal_today():
        messages.error(
            request,
            f"Daily AI proposal limit reached ({plan_limits()['ai_proposals_per_day']}). "
            "Try again tomorrow or upgrade the plan.",
        )
        return redirect("finding_detail", finding_id=finding.id)
    proposal = create_remediation_proposal(finding, requested_by=request.user)
    if proposal.status == proposal.Status.GENERATED:
        messages.success(request, "AI fix proposal generated.")
    else:
        messages.info(
            request,
            "AI was unavailable; a template proposal was generated from the evidence.",
        )
    return redirect("finding_detail", finding_id=finding.id)


@product_login_required
@require_POST
def finding_github_issue(request: HttpRequest, finding_id) -> HttpResponse:
    finding = get_object_or_404(
        Finding.objects.select_related("account").filter(
            account__in=accessible_accounts(request.user)
        ),
        id=finding_id,
    )
    if not has_account_role(request.user, finding.account, AccountMembership.Role.OPERATOR):
        messages.error(request, "You need operator access to create GitHub issues.")
        return redirect("finding_detail", finding_id=finding.id)
    ok, message = create_github_issue(finding)
    if ok:
        messages.success(request, f"GitHub issue created: {message}")
    else:
        messages.error(request, message)
    return redirect("finding_detail", finding_id=finding.id)


@csrf_exempt
@require_POST
def stripe_webhook(request: HttpRequest) -> JsonResponse:
    """Stripe billing webhook: activates/deactivates the paid plan.

    Signature-verified with STRIPE_WEBHOOK_SECRET; disabled (404) when no
    secret is configured.
    """
    from django.conf import settings as django_settings

    from .billing import apply_stripe_event, parse_stripe_payload, verify_stripe_signature

    secret = django_settings.STRIPE_WEBHOOK_SECRET
    if not secret:
        return JsonResponse({"error": "billing webhook disabled"}, status=404)
    signature = request.headers.get("Stripe-Signature", "")
    if not verify_stripe_signature(request.body, signature, secret):
        return JsonResponse({"error": "invalid signature"}, status=400)
    try:
        event = parse_stripe_payload(request.body)
    except ValueError:
        return JsonResponse({"error": "invalid payload"}, status=400)
    outcome = apply_stripe_event(event)
    return JsonResponse({"received": True, "outcome": outcome})


@global_admin_required
@require_POST
def invitation_create(request: HttpRequest) -> HttpResponse:
    from .forms import InvitationForm

    form = InvitationForm(request.POST, accounts=CloudAccount.objects.all())
    if form.is_valid():
        invitation = form.save(request.user)
        accept_url = request.build_absolute_uri(
            reverse("invitation_accept", args=[invitation.token])
        )
        messages.success(
            request,
            f"Invitation created. Share this link (valid 7 days): {accept_url}",
        )
    else:
        messages.error(request, "Could not create the invitation.")
    return redirect("users")


@require_http_methods(["GET", "POST"])
def invitation_accept(request: HttpRequest, token: str) -> HttpResponse:
    from .billing import can_add_user
    from .models import Invitation

    invitation = Invitation.objects.filter(token=token).first()
    if invitation is None or not invitation.is_usable:
        return render(request, "ops/invite_invalid.html", status=410)
    if not can_add_user():
        return render(request, "ops/invite_invalid.html", {"seats_full": True}, status=410)

    if request.method == "POST":
        form = SetupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_staff = invitation.is_global_admin
            user.is_superuser = invitation.is_global_admin
            user.save()
            for account_id, role in (invitation.account_roles or {}).items():
                account = CloudAccount.objects.filter(id=account_id).first()
                if account and role in AccountMembership.Role.values:
                    AccountMembership.objects.update_or_create(
                        user=user, account=account, defaults={"role": role}
                    )
            invitation.accepted_by = user
            invitation.accepted_at = timezone.now()
            invitation.save(update_fields=["accepted_by", "accepted_at"])
            login(request, user)
            messages.success(request, "Welcome to InfraLens.")
            return redirect("dashboard")
    else:
        form = SetupForm()
    return render(
        request,
        "ops/invite_accept.html",
        {"form": form, "invitation": invitation},
    )


@require_GET
def metrics(request: HttpRequest) -> HttpResponse:
    """Prometheus-style metrics. Disabled unless INFRALENS_METRICS_TOKEN is set."""
    from django.conf import settings as django_settings

    from .models import BackgroundJob, ScanRun, ScanSchedule

    token = django_settings.METRICS_TOKEN
    if not token:
        return HttpResponse(status=404)
    supplied = request.GET.get("token", "") or request.headers.get(
        "Authorization", ""
    ).removeprefix("Bearer ").strip()
    if not constant_time_compare(supplied, token):
        return HttpResponse(status=403)

    lines = [
        "# TYPE infralens_accounts gauge",
        f"infralens_accounts {CloudAccount.objects.count()}",
        "# TYPE infralens_resources gauge",
        f"infralens_resources {sum(a.resources.count() for a in CloudAccount.objects.all())}",
        "# TYPE infralens_open_findings gauge",
    ]
    open_findings = Finding.objects.filter(status=Finding.Status.OPEN)
    for severity, _ in Finding.Severity.choices:
        count = open_findings.filter(severity=severity).count()
        lines.append(f'infralens_open_findings{{severity="{severity}"}} {count}')
    lines.append("# TYPE infralens_scan_runs_total counter")
    for status, _ in ScanRun.Status.choices:
        count = ScanRun.objects.filter(status=status).count()
        lines.append(f'infralens_scan_runs_total{{status="{status}"}} {count}')
    lines.append("# TYPE infralens_schedules_due gauge")
    due = sum(1 for s in ScanSchedule.objects.filter(enabled=True) if s.is_due())
    lines.append(f"infralens_schedules_due {due}")
    lines.append("# TYPE infralens_jobs gauge")
    for status, _ in BackgroundJob.Status.choices:
        count = BackgroundJob.objects.filter(status=status).count()
        lines.append(f'infralens_jobs{{status="{status}"}} {count}')
    return HttpResponse("\n".join(lines) + "\n", content_type="text/plain; version=0.0.4")


@product_login_required
@require_POST
def briefing_create(request: HttpRequest) -> HttpResponse:
    account_id = request.POST.get("account_id")
    account = None
    if account_id:
        account = get_object_or_404(accessible_accounts(request.user), id=account_id)
        if not has_account_role(request.user, account, AccountMembership.Role.OPERATOR):
            messages.error(request, "You need operator access to generate briefings.")
            return redirect("account_detail", account_id=account.id)
    elif not (request.user.is_superuser or request.user.is_staff):
        messages.error(request, "Choose an account briefing to regenerate.")
        return redirect("dashboard")
    briefing = generate_daily_briefing(account)
    messages.success(request, f"Created briefing: {briefing.title}")
    if account:
        return redirect("account_detail", account_id=account.id)
    return redirect("dashboard")


@product_login_required
@require_GET
def findings_table(request: HttpRequest) -> HttpResponse:
    severity = request.GET.get("severity", "")
    category = request.GET.get("category", "")
    query = request.GET.get("q", "")
    findings = Finding.objects.select_related("account").filter(
        account__in=accessible_accounts(request.user),
        status=Finding.Status.OPEN,
    )
    if severity:
        findings = findings.filter(severity=severity)
    if category:
        findings = findings.filter(category=category)
    if query:
        findings = findings.filter(title__icontains=query)
    return render(request, "ops/partials/findings_table.html", {"findings": findings[:80]})


@product_login_required
@require_GET
def finding_detail(request: HttpRequest, finding_id) -> HttpResponse:
    finding = get_object_or_404(
        Finding.objects.select_related("account").filter(
            account__in=accessible_accounts(request.user)
        ),
        id=finding_id,
    )
    template = "ops/partials/finding_detail.html" if request.headers.get("HX-Request") else "ops/finding_detail.html"
    return render(
        request,
        template,
        {
            "finding": finding,
            "proposals": finding.proposals.select_related("requested_by")[:5],
            "can_propose": has_account_role(
                request.user, finding.account, AccountMembership.Role.OPERATOR
            ),
        },
    )


@global_admin_required
@require_POST
def demo_seed(request: HttpRequest) -> HttpResponse:
    account = seed_demo_data()
    AccountMembership.objects.update_or_create(
        user=request.user,
        account=account,
        defaults={"role": AccountMembership.Role.OWNER},
    )
    messages.success(request, "Demo account and findings were loaded.")
    return redirect("account_detail", account_id=account.id)


@global_admin_required
@require_GET
def user_list(request: HttpRequest) -> HttpResponse:
    from .forms import InvitationForm
    from .models import Invitation

    users = get_user_model().objects.order_by("username")
    return render(
        request,
        "ops/users.html",
        {
            "users": users,
            "invitation_form": InvitationForm(accounts=CloudAccount.objects.all()),
            "pending_invitations": [
                invitation
                for invitation in Invitation.objects.filter(accepted_by__isnull=True)[:10]
                if invitation.is_usable
            ],
        },
    )


@global_admin_required
@require_http_methods(["GET", "POST"])
def user_create(request: HttpRequest) -> HttpResponse:
    from .billing import can_add_user, plan_limits

    if not can_add_user():
        messages.error(
            request,
            f"Your plan allows {plan_limits()['seats']} user(s). "
            "Upgrade the plan to add more.",
        )
        return redirect("users")
    if request.method == "POST":
        form = ProductUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, f"User {user.username} was created.")
            return redirect("user_access", user_id=user.id)
    else:
        form = ProductUserCreationForm()
    return render(request, "ops/user_form.html", {"form": form})


@global_admin_required
@require_http_methods(["GET", "POST"])
def user_access(request: HttpRequest, user_id) -> HttpResponse:
    user_obj = get_object_or_404(get_user_model(), id=user_id)
    accounts = CloudAccount.objects.all()
    if request.method == "POST":
        form = UserAccessForm(request.POST, user_obj=user_obj, accounts=accounts)
        if form.is_valid():
            form.save()
            messages.success(request, f"Access updated for {user_obj.username}.")
            return redirect("users")
    else:
        form = UserAccessForm(user_obj=user_obj, accounts=accounts)
    return render(request, "ops/user_access.html", {"form": form, "user_obj": user_obj})


@product_login_required
@require_GET
def webhook_list(request: HttpRequest) -> HttpResponse:
    endpoints = WebhookEndpoint.objects.filter(user=request.user)
    subscriptions = NotificationSubscription.objects.select_related(
        "endpoint",
        "account",
    ).filter(endpoint__user=request.user)
    deliveries = NotificationDelivery.objects.select_related("endpoint", "scan_run").filter(
        endpoint__user=request.user
    )[:20]
    return render(
        request,
        "ops/webhooks.html",
        {
            "endpoints": endpoints,
            "subscriptions": subscriptions,
            "deliveries": deliveries,
        },
    )


@product_login_required
@require_http_methods(["GET", "POST"])
def webhook_create(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = WebhookEndpointForm(request.POST)
        if form.is_valid():
            endpoint = form.save(request.user)
            messages.success(request, f"Webhook {endpoint.name} was created.")
            return redirect("webhooks")
    else:
        form = WebhookEndpointForm()
    return render(request, "ops/webhook_form.html", {"form": form})


@product_login_required
@require_http_methods(["GET", "POST"])
def subscription_create(request: HttpRequest) -> HttpResponse:
    accounts = accessible_accounts(request.user)
    if request.method == "POST":
        form = NotificationSubscriptionForm(request.POST, user=request.user, accounts=accounts)
        if form.is_valid():
            form.save()
            messages.success(request, "Notification subscription was created.")
            return redirect("webhooks")
    else:
        form = NotificationSubscriptionForm(user=request.user, accounts=accounts)
    return render(request, "ops/subscription_form.html", {"form": form})


@require_GET
def healthz(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})
