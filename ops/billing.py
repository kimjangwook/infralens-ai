from __future__ import annotations

"""Plan tiers, usage metering, and Stripe webhook verification.

The self-hosted core stays fully functional on the Free tier; paid tiers only
raise operational limits. Plan state lives in ``GlobalSettings`` and is
activated either manually (admin) or by the Stripe webhook.
"""

import hashlib
import hmac
import json
from datetime import date, datetime, timezone as dt_timezone

from django.db.models import F
from django.utils import timezone

from .models import CloudAccount, GlobalSettings, UsageRecord


PLAN_LIMITS = {
    GlobalSettings.Plan.FREE: {
        "accounts": 2,
        "seats": 3,
        "ai_proposals_per_day": 10,
        "history_days": 30,
    },
    GlobalSettings.Plan.PRO: {
        "accounts": 25,
        "seats": 10,
        "ai_proposals_per_day": 200,
        "history_days": 365,
    },
    GlobalSettings.Plan.TEAM: {
        "accounts": 1000,
        "seats": 1000,
        "ai_proposals_per_day": 2000,
        "history_days": 730,
    },
}


def effective_plan() -> str:
    settings_obj = GlobalSettings.load()
    if settings_obj.plan != GlobalSettings.Plan.FREE:
        if settings_obj.plan_valid_until and settings_obj.plan_valid_until < date.today():
            return GlobalSettings.Plan.FREE
        return settings_obj.plan
    return GlobalSettings.Plan.FREE


def plan_limits() -> dict:
    return PLAN_LIMITS[effective_plan()]


def can_add_account() -> bool:
    return CloudAccount.objects.count() < plan_limits()["accounts"]


def can_add_user() -> bool:
    from django.contrib.auth import get_user_model

    return get_user_model().objects.count() < plan_limits()["seats"]


def can_generate_proposal_today() -> bool:
    used = usage_today(UsageRecord.Kind.AI_CALL)
    return used < plan_limits()["ai_proposals_per_day"]


def record_usage(kind: str, count: int = 1) -> None:
    record, created = UsageRecord.objects.get_or_create(
        date=timezone.now().date(),
        kind=kind,
        defaults={"count": count},
    )
    if not created:
        UsageRecord.objects.filter(pk=record.pk).update(count=F("count") + count)


def usage_today(kind: str) -> int:
    record = UsageRecord.objects.filter(date=timezone.now().date(), kind=kind).first()
    return record.count if record else 0


def usage_this_month() -> dict:
    today = timezone.now().date()
    start = today.replace(day=1)
    totals = {kind: 0 for kind, _ in UsageRecord.Kind.choices}
    for record in UsageRecord.objects.filter(date__gte=start):
        totals[record.kind] = totals.get(record.kind, 0) + record.count
    return totals


def verify_stripe_signature(payload: bytes, header: str, secret: str, tolerance: int = 300) -> bool:
    """Verify a Stripe-Signature header (t=...,v1=...) without the SDK."""
    if not header or not secret:
        return False
    parts = dict(
        item.split("=", 1) for item in header.split(",") if "=" in item
    )
    timestamp = parts.get("t", "")
    signature = parts.get("v1", "")
    if not timestamp or not signature:
        return False
    try:
        age = abs(int(timezone.now().timestamp()) - int(timestamp))
    except ValueError:
        return False
    if age > tolerance:
        return False
    signed_payload = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def apply_stripe_event(event: dict) -> str:
    """Update the plan from a verified Stripe event. Returns a short outcome."""
    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})
    settings_obj = GlobalSettings.load()

    if event_type in {"checkout.session.completed", "customer.subscription.updated"}:
        plan = (data.get("metadata") or {}).get("infralens_plan", "")
        if plan not in {GlobalSettings.Plan.PRO, GlobalSettings.Plan.TEAM}:
            return "ignored: no infralens_plan metadata"
        settings_obj.plan = plan
        period_end = data.get("current_period_end")
        if period_end:
            settings_obj.plan_valid_until = datetime.fromtimestamp(
                int(period_end), tz=dt_timezone.utc
            ).date()
        else:
            settings_obj.plan_valid_until = None
        customer = data.get("customer", "")
        if customer:
            settings_obj.stripe_customer_id = customer
        settings_obj.save(
            update_fields=["plan", "plan_valid_until", "stripe_customer_id", "updated_at"]
        )
        return f"plan set to {plan}"

    if event_type == "customer.subscription.deleted":
        settings_obj.plan = GlobalSettings.Plan.FREE
        settings_obj.plan_valid_until = None
        settings_obj.save(update_fields=["plan", "plan_valid_until", "updated_at"])
        return "plan reverted to free"

    return f"ignored: {event_type}"


def parse_stripe_payload(payload: bytes) -> dict:
    return json.loads(payload.decode("utf-8"))
