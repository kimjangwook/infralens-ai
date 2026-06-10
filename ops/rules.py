from __future__ import annotations

"""Custom rule engine: evaluates user-defined detectors after each scan."""

import re
from typing import Any

from django.db.models import Q

from .models import CloudAccount, CustomRule, Finding, ScanRun


def evaluate_custom_rules(account: CloudAccount, scan_run: ScanRun) -> int:
    rules = CustomRule.objects.filter(enabled=True).filter(
        Q(account__isnull=True) | Q(account=account)
    )
    created = 0
    for rule in rules:
        if rule.target == CustomRule.Target.RESOURCE:
            items = account.resources.all()
        else:
            items = account.schedules.all()
        for item in items:
            value = _resolve_field(item, rule.field_path)
            if value is None:
                continue
            if _matches(rule.operator, value, rule.value):
                _create_rule_finding(account, scan_run, rule, item, value)
                created += 1
    return created


def _resolve_field(item: Any, field_path: str) -> Any:
    """Walk ``a.b.c`` through model attributes, then into JSON metadata."""
    current: Any = item
    for part in field_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
        if current is None:
            return None
    if isinstance(current, (dict, list)):
        return None
    return current


def _matches(operator: str, value: Any, expected: str) -> bool:
    text = str(value)
    if operator == CustomRule.Operator.EQUALS:
        return text == expected
    if operator == CustomRule.Operator.NOT_EQUALS:
        return text != expected
    if operator == CustomRule.Operator.CONTAINS:
        return expected.lower() in text.lower()
    if operator == CustomRule.Operator.NOT_CONTAINS:
        return expected.lower() not in text.lower()
    if operator in {CustomRule.Operator.GT, CustomRule.Operator.LT}:
        try:
            number, bound = float(text), float(expected)
        except (TypeError, ValueError):
            return False
        return number > bound if operator == CustomRule.Operator.GT else number < bound
    if operator == CustomRule.Operator.REGEX:
        try:
            return re.search(expected, text) is not None
        except re.error:
            return False
    return False


def _create_rule_finding(
    account: CloudAccount,
    scan_run: ScanRun,
    rule: CustomRule,
    item: Any,
    matched_value: Any,
) -> None:
    from .scanners.common import upsert_finding

    upsert_finding(
        account,
        scan_run,
        rule.severity,
        "custom",
        f"[{rule.name}] {item.name}",
        resource_ref=getattr(item, "provider_id", ""),
        evidence={
            "rule": rule.name,
            "target": rule.target,
            "field": rule.field_path,
            "operator": rule.operator,
            "expected": rule.value,
            "matched_value": str(matched_value)[:300],
        },
        suggested_action=rule.suggested_action
        or "Review this custom rule match and decide manually.",
    )
