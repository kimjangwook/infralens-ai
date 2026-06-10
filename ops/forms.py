from __future__ import annotations

import json

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm

from .crypto import credential_hint, encrypt_json, encrypt_text, secret_hint
from .models import (
    AccountMembership,
    AIProvider,
    CloudAccount,
    CustomRule,
    GlobalSettings,
    NotificationSubscription,
    ScanSchedule,
    WebhookEndpoint,
)


AWS_REGION_CHOICES = [
    ("ap-northeast-1", "Asia Pacific (Tokyo) - ap-northeast-1"),
    ("ap-northeast-2", "Asia Pacific (Seoul) - ap-northeast-2"),
    ("ap-northeast-3", "Asia Pacific (Osaka) - ap-northeast-3"),
    ("ap-southeast-1", "Asia Pacific (Singapore) - ap-southeast-1"),
    ("ap-southeast-2", "Asia Pacific (Sydney) - ap-southeast-2"),
    ("ap-southeast-3", "Asia Pacific (Jakarta) - ap-southeast-3"),
    ("ap-south-1", "Asia Pacific (Mumbai) - ap-south-1"),
    ("us-east-1", "US East (N. Virginia) - us-east-1"),
    ("us-east-2", "US East (Ohio) - us-east-2"),
    ("us-west-1", "US West (N. California) - us-west-1"),
    ("us-west-2", "US West (Oregon) - us-west-2"),
    ("ca-central-1", "Canada (Central) - ca-central-1"),
    ("eu-west-1", "Europe (Ireland) - eu-west-1"),
    ("eu-west-2", "Europe (London) - eu-west-2"),
    ("eu-west-3", "Europe (Paris) - eu-west-3"),
    ("eu-central-1", "Europe (Frankfurt) - eu-central-1"),
    ("eu-north-1", "Europe (Stockholm) - eu-north-1"),
    ("sa-east-1", "South America (Sao Paulo) - sa-east-1"),
]

GCP_LOCATION_CHOICES = [
    ("asia-northeast1", "Tokyo - asia-northeast1"),
    ("asia-northeast2", "Osaka - asia-northeast2"),
    ("asia-northeast3", "Seoul - asia-northeast3"),
    ("asia-southeast1", "Singapore - asia-southeast1"),
    ("asia-southeast2", "Jakarta - asia-southeast2"),
    ("asia-east1", "Taiwan - asia-east1"),
    ("asia-east2", "Hong Kong - asia-east2"),
    ("us-central1", "Iowa - us-central1"),
    ("us-east1", "South Carolina - us-east1"),
    ("us-east4", "N. Virginia - us-east4"),
    ("us-west1", "Oregon - us-west1"),
    ("us-west2", "Los Angeles - us-west2"),
    ("europe-west1", "Belgium - europe-west1"),
    ("europe-west2", "London - europe-west2"),
    ("europe-west3", "Frankfurt - europe-west3"),
    ("europe-west4", "Netherlands - europe-west4"),
]

AI_MODEL_SUGGESTIONS = {
    "openai": [
        "gpt-5.5",
        "gpt-5.5-2026-04-23",
        "gpt-5.4-mini-2026-03-17",
    ],
    "anthropic": [
        "claude-opus-4-8",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
    ],
    "google": [
        "gemini-3.1-pro-preview",
        "gemini-3.5-flash",
        "gemini-3.1-flash-lite",
    ],
}


class CloudAccountForm(forms.ModelForm):
    aws_account_ref = forms.CharField(
        label="AWS account id or alias",
        required=False,
    )
    aws_access_key_id = forms.CharField(label="AWS access key id", required=False)
    aws_secret_access_key = forms.CharField(
        label="AWS secret access key",
        required=False,
        widget=forms.PasswordInput(render_value=True),
    )
    aws_session_token = forms.CharField(
        label="AWS session token",
        required=False,
        widget=forms.PasswordInput(render_value=True),
    )
    aws_regions = forms.MultipleChoiceField(
        label="AWS regions",
        choices=AWS_REGION_CHOICES,
        initial=["ap-northeast-1", "us-east-1"],
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )
    gcp_project_id = forms.CharField(
        label="GCP project id",
        required=False,
        help_text="Optional when the service account JSON includes project_id.",
    )
    gcp_service_account_json = forms.CharField(
        label="GCP service account JSON",
        required=False,
        widget=forms.Textarea(attrs={"rows": 8}),
    )
    gcp_locations = forms.MultipleChoiceField(
        label="GCP locations",
        choices=GCP_LOCATION_CHOICES,
        initial=["asia-northeast1", "us-central1"],
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )
    gcp_billing_export_table = forms.CharField(
        label="BigQuery billing export table",
        required=False,
        help_text="Optional, project.dataset.table. Enables service-level GCP cost anomaly checks.",
    )
    k8s_api_server = forms.CharField(
        label="Kubernetes API server URL",
        required=False,
        help_text="e.g. https://203.0.113.10:6443",
    )
    k8s_bearer_token = forms.CharField(
        label="Kubernetes bearer token",
        required=False,
        widget=forms.PasswordInput(render_value=True),
        help_text="Token of a read-only (view ClusterRole) ServiceAccount.",
    )
    k8s_verify_tls = forms.BooleanField(
        label="Verify Kubernetes TLS certificate",
        required=False,
        initial=True,
    )
    azure_tenant_id = forms.CharField(label="Azure tenant id", required=False)
    azure_client_id = forms.CharField(label="Azure client id", required=False)
    azure_client_secret = forms.CharField(
        label="Azure client secret",
        required=False,
        widget=forms.PasswordInput(render_value=True),
    )
    azure_subscription_id = forms.CharField(label="Azure subscription id", required=False)

    class Meta:
        model = CloudAccount
        fields = ["name", "provider"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_edit = self.instance.pk is not None
        if not self.is_edit:
            return
        # Prefill existing region and account reference for editing. Credentials
        # are encrypted and never re-displayed; leaving them blank keeps the
        # stored values.
        account = self.instance
        if account.provider == CloudAccount.Provider.AWS:
            self.fields["aws_account_ref"].initial = account.account_ref
            self.fields["aws_regions"].initial = account.regions
        elif account.provider == CloudAccount.Provider.GCP:
            self.fields["gcp_project_id"].initial = account.account_ref
            self.fields["gcp_locations"].initial = account.regions
            self.fields["gcp_billing_export_table"].initial = (
                account.options or {}
            ).get("gcp_billing_export_table", "")
        elif account.provider == CloudAccount.Provider.K8S:
            self.fields["k8s_api_server"].initial = account.account_ref
        elif account.provider == CloudAccount.Provider.AZURE:
            self.fields["azure_subscription_id"].initial = account.account_ref

    def _credentials_provided(self, provider: str, cleaned: dict) -> bool:
        if provider == CloudAccount.Provider.AWS:
            return bool(
                cleaned.get("aws_access_key_id") or cleaned.get("aws_secret_access_key")
            )
        if provider == CloudAccount.Provider.GCP:
            return bool(cleaned.get("gcp_service_account_json"))
        if provider == CloudAccount.Provider.K8S:
            return bool(cleaned.get("k8s_bearer_token"))
        if provider == CloudAccount.Provider.AZURE:
            return bool(cleaned.get("azure_client_secret"))
        return False

    def clean(self) -> dict:
        cleaned = super().clean()
        provider = cleaned.get("provider")
        # On edit, unchanged credentials may be omitted to keep the stored ones.
        provider_changed = self.is_edit and provider != self.instance.provider
        keep_existing = (
            self.is_edit
            and not provider_changed
            and not self._credentials_provided(provider, cleaned)
        )
        self.keep_existing_credentials = keep_existing

        if provider == CloudAccount.Provider.AWS:
            if not keep_existing and (
                not cleaned.get("aws_access_key_id")
                or not cleaned.get("aws_secret_access_key")
            ):
                raise forms.ValidationError("AWS access key id and secret access key are required.")
            if not cleaned.get("aws_regions"):
                raise forms.ValidationError("Select at least one AWS region.")
        if provider == CloudAccount.Provider.GCP:
            raw_json = cleaned.get("gcp_service_account_json", "")
            if not raw_json:
                if not keep_existing:
                    raise forms.ValidationError("GCP service account JSON is required.")
            else:
                try:
                    parsed = json.loads(raw_json)
                except json.JSONDecodeError as exc:
                    raise forms.ValidationError("GCP service account JSON is not valid JSON.") from exc
                if parsed.get("type") != "service_account":
                    raise forms.ValidationError("GCP credential must be a service account JSON.")
                cleaned["gcp_service_account"] = parsed
            if not cleaned.get("gcp_locations"):
                raise forms.ValidationError("Select at least one GCP location.")
        if provider == CloudAccount.Provider.K8S and not keep_existing:
            if not cleaned.get("k8s_api_server") or not cleaned.get("k8s_bearer_token"):
                raise forms.ValidationError(
                    "Kubernetes API server URL and bearer token are required."
                )
        if provider == CloudAccount.Provider.AZURE and not keep_existing:
            missing = [
                field
                for field in (
                    "azure_tenant_id",
                    "azure_client_id",
                    "azure_client_secret",
                    "azure_subscription_id",
                )
                if not cleaned.get(field)
            ]
            if missing:
                raise forms.ValidationError(
                    "Azure tenant, client id, client secret, and subscription id are required."
                )
        return cleaned

    def save(self, commit: bool = True) -> CloudAccount:
        account = super().save(commit=False)
        keep_existing = getattr(self, "keep_existing_credentials", False)
        payload = None
        if account.provider == CloudAccount.Provider.AWS:
            account.account_ref = self.cleaned_data.get("aws_account_ref", "")
            account.regions = self.cleaned_data["aws_regions"]
            if not keep_existing:
                payload = {
                    "aws_access_key_id": self.cleaned_data["aws_access_key_id"],
                    "aws_secret_access_key": self.cleaned_data["aws_secret_access_key"],
                    "aws_session_token": self.cleaned_data.get("aws_session_token", ""),
                }
        elif account.provider == CloudAccount.Provider.GCP:
            account.regions = self.cleaned_data["gcp_locations"]
            options = dict(account.options or {})
            billing_table = self.cleaned_data.get("gcp_billing_export_table", "").strip()
            if billing_table:
                options["gcp_billing_export_table"] = billing_table
            else:
                options.pop("gcp_billing_export_table", None)
            account.options = options
            if keep_existing:
                account.account_ref = (
                    self.cleaned_data.get("gcp_project_id", "") or account.account_ref
                )
            else:
                payload = self.cleaned_data["gcp_service_account"]
                account.account_ref = self.cleaned_data.get("gcp_project_id", "") or payload.get(
                    "project_id", ""
                )
        elif account.provider == CloudAccount.Provider.K8S:
            api_server = self.cleaned_data.get("k8s_api_server", "").strip()
            if api_server:
                account.account_ref = api_server
            if not keep_existing:
                payload = {
                    "api_server": api_server or account.account_ref,
                    "token": self.cleaned_data["k8s_bearer_token"],
                    "verify_tls": self.cleaned_data.get("k8s_verify_tls", True),
                }
        elif account.provider == CloudAccount.Provider.AZURE:
            subscription = self.cleaned_data.get("azure_subscription_id", "").strip()
            if subscription:
                account.account_ref = subscription
            if not keep_existing:
                payload = {
                    "tenant_id": self.cleaned_data["azure_tenant_id"],
                    "client_id": self.cleaned_data["azure_client_id"],
                    "client_secret": self.cleaned_data["azure_client_secret"],
                    "subscription_id": subscription or account.account_ref,
                }

        if payload is not None:
            account.encrypted_credentials = encrypt_json(payload)
            account.credentials_hint = credential_hint(account.provider, payload)
        if commit:
            account.save()
        return account


class GlobalSettingsForm(forms.ModelForm):
    github_token = forms.CharField(
        label="GitHub token",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text=(
            "Fine-grained token with issues:write on the repository. Stored "
            "encrypted; leave blank to keep the current token."
        ),
    )

    class Meta:
        model = GlobalSettings
        fields = [
            "report_language",
            "daily_report_enabled",
            "daily_report_hour",
            "github_repo",
        ]

    def clean_daily_report_hour(self) -> int:
        hour = self.cleaned_data.get("daily_report_hour") or 0
        if hour > 23:
            raise forms.ValidationError("Use an hour between 0 and 23 (UTC).")
        return hour

    def save(self, commit: bool = True) -> GlobalSettings:
        settings_obj = super().save(commit=False)
        token = (self.cleaned_data.get("github_token") or "").strip()
        if token:
            settings_obj.encrypted_github_token = encrypt_text(token)
            settings_obj.github_token_hint = secret_hint(token)
        if commit:
            settings_obj.save()
        return settings_obj


class AIProviderForm(forms.ModelForm):
    api_key = forms.CharField(
        label="API key",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Stored encrypted. Leave blank when editing to keep the current key.",
    )

    class Meta:
        model = AIProvider
        fields = ["name", "provider", "model", "is_active", "is_default"]
        widgets = {
            "model": forms.TextInput(
                attrs={"placeholder": "e.g. gpt-5.5, claude-opus-4-8, gemini-3.5-flash"}
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_edit = self.instance.pk is not None

    def clean_api_key(self) -> str:
        api_key = (self.cleaned_data.get("api_key") or "").strip()
        if not api_key and not self.is_edit:
            raise forms.ValidationError("An API key is required.")
        return api_key

    def save(self, commit: bool = True) -> AIProvider:
        provider = super().save(commit=False)
        api_key = self.cleaned_data.get("api_key", "")
        if api_key:
            provider.encrypted_api_key = encrypt_text(api_key)
            provider.api_key_hint = secret_hint(api_key)
        if commit:
            provider.save()
        return provider


class SetupForm(UserCreationForm):
    email = forms.EmailField(required=False)

    class Meta:
        model = get_user_model()
        fields = ["username", "email", "password1", "password2"]


class ProductLoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={"autofocus": True}))


class ProductUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=False)
    is_global_admin = forms.BooleanField(
        label="Global admin",
        required=False,
        help_text="Allows user management, global settings, and cloud account creation.",
    )

    class Meta:
        model = get_user_model()
        fields = ["username", "email", "password1", "password2", "is_global_admin"]

    def save(self, commit: bool = True):
        user = super().save(commit=False)
        user.email = self.cleaned_data.get("email", "")
        user.is_staff = self.cleaned_data.get("is_global_admin", False)
        user.is_superuser = self.cleaned_data.get("is_global_admin", False)
        if commit:
            user.save()
        return user


class UserAccessForm(forms.Form):
    ROLE_CHOICES = [("", "No access")] + list(AccountMembership.Role.choices)

    def __init__(self, *args, user_obj, accounts, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_obj = user_obj
        self.accounts = list(accounts)
        memberships = {
            membership.account_id: membership.role
            for membership in AccountMembership.objects.filter(user=user_obj)
        }
        for account in self.accounts:
            self.fields[f"account_{account.id}"] = forms.ChoiceField(
                label=f"{account.name} ({account.get_provider_display()})",
                choices=self.ROLE_CHOICES,
                required=False,
                initial=memberships.get(account.id, ""),
            )

    def save(self) -> None:
        for account in self.accounts:
            role = self.cleaned_data.get(f"account_{account.id}", "")
            if role:
                AccountMembership.objects.update_or_create(
                    user=self.user_obj,
                    account=account,
                    defaults={"role": role},
                )
            else:
                AccountMembership.objects.filter(user=self.user_obj, account=account).delete()


class CustomRuleForm(forms.ModelForm):
    class Meta:
        model = CustomRule
        fields = [
            "name",
            "account",
            "target",
            "field_path",
            "operator",
            "value",
            "severity",
            "suggested_action",
            "enabled",
        ]
        widgets = {
            "field_path": forms.TextInput(
                attrs={"placeholder": "e.g. name, state, metadata.timeout"}
            ),
            "suggested_action": forms.Textarea(attrs={"rows": 2}),
        }


class InvitationForm(forms.Form):
    note = forms.CharField(label="Note", required=False, max_length=160)
    is_global_admin = forms.BooleanField(label="Global admin", required=False)
    role = forms.ChoiceField(
        label="Role on selected accounts",
        choices=AccountMembership.Role.choices,
        initial=AccountMembership.Role.VIEWER,
    )
    invite_accounts = forms.ModelMultipleChoiceField(
        label="Cloud accounts",
        queryset=CloudAccount.objects.none(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    def __init__(self, *args, accounts, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["invite_accounts"].queryset = accounts

    def save(self, invited_by):
        from datetime import timedelta

        from django.utils import timezone

        from .models import Invitation

        role = self.cleaned_data["role"]
        return Invitation.objects.create(
            note=self.cleaned_data.get("note", ""),
            invited_by=invited_by,
            is_global_admin=self.cleaned_data.get("is_global_admin", False),
            account_roles={
                str(account.id): role
                for account in self.cleaned_data.get("invite_accounts", [])
            },
            expires_at=timezone.now() + timedelta(days=7),
        )


class ScanScheduleForm(forms.ModelForm):
    class Meta:
        model = ScanSchedule
        fields = ["enabled", "interval_minutes"]
        labels = {"interval_minutes": "Scan interval"}


class WebhookEndpointForm(forms.ModelForm):
    webhook_url = forms.CharField(
        label="Webhook URL or token",
        help_text=(
            "Generic/Slack: the incoming webhook URL. Notion: the integration "
            "token (secret_...)."
        ),
    )
    notion_parent_page_id = forms.CharField(
        label="Notion parent page id",
        required=False,
        help_text="Required for Notion endpoints; scan pages are created under it.",
    )

    class Meta:
        model = WebhookEndpoint
        fields = ["name", "provider", "receive_daily_report", "is_active"]

    def clean(self) -> dict:
        cleaned = super().clean()
        provider = cleaned.get("provider")
        target = (cleaned.get("webhook_url") or "").strip()
        if provider == WebhookEndpoint.Provider.NOTION:
            if not cleaned.get("notion_parent_page_id", "").strip():
                raise forms.ValidationError("Notion endpoints need a parent page id.")
        elif target and not target.startswith(("http://", "https://")):
            raise forms.ValidationError("Webhook URL must start with http:// or https://.")
        cleaned["webhook_url"] = target
        return cleaned

    def save(self, user, commit: bool = True):
        endpoint = super().save(commit=False)
        url = self.cleaned_data["webhook_url"]
        endpoint.user = user
        endpoint.encrypted_url = encrypt_text(url)
        endpoint.url_hint = (
            secret_hint(url)
            if endpoint.provider == WebhookEndpoint.Provider.NOTION
            else _url_hint(url)
        )
        if endpoint.provider == WebhookEndpoint.Provider.NOTION:
            endpoint.config = {
                "notion_parent_page_id": self.cleaned_data["notion_parent_page_id"].strip()
            }
        if commit:
            endpoint.save()
        return endpoint


class NotificationSubscriptionForm(forms.ModelForm):
    class Meta:
        model = NotificationSubscription
        fields = ["endpoint", "account", "min_severity", "enabled"]

    def __init__(self, *args, user, accounts, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["endpoint"].queryset = WebhookEndpoint.objects.filter(
            user=user,
            is_active=True,
        )
        self.fields["account"].queryset = accounts


def _url_hint(url: str) -> str:
    if len(url) <= 42:
        return url
    return f"{url[:24]}...{url[-14:]}"
