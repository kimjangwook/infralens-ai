from __future__ import annotations

from functools import wraps
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import reverse

from .models import AccountMembership, CloudAccount


ROLE_RANK = {
    AccountMembership.Role.VIEWER: 10,
    AccountMembership.Role.OPERATOR: 20,
    AccountMembership.Role.ADMIN: 30,
    AccountMembership.Role.OWNER: 40,
}


def users_exist() -> bool:
    return get_user_model().objects.exists()


def product_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not users_exist():
            return redirect("setup")
        if not request.user.is_authenticated:
            query = urlencode({"next": request.get_full_path()})
            return redirect(f"{reverse('login')}?{query}")
        return view_func(request, *args, **kwargs)

    return wrapper


def global_admin_required(view_func):
    @product_login_required
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_superuser or request.user.is_staff:
            return view_func(request, *args, **kwargs)
        return redirect("dashboard")

    return wrapper


def accessible_accounts(user):
    if user.is_superuser or user.is_staff:
        return CloudAccount.objects.all()
    return CloudAccount.objects.filter(memberships__user=user).distinct()


def has_account_role(user, account: CloudAccount, minimum_role: str) -> bool:
    if user.is_superuser or user.is_staff:
        return True
    membership = AccountMembership.objects.filter(user=user, account=account).first()
    if not membership:
        return False
    return ROLE_RANK.get(membership.role, 0) >= ROLE_RANK[minimum_role]

