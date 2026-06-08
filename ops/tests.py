from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .crypto import decrypt_json, decrypt_text
from .forms import AIProviderForm, CloudAccountForm, WebhookEndpointForm
from .models import (
    AccountMembership,
    AIProvider,
    CloudAccount,
    DailyBriefing,
    Finding,
    GlobalSettings,
    WebhookEndpoint,
)
from .services import generate_daily_briefing, seed_demo_data
from .templatetags.markdown_extras import render_markdown


class CloudAccountFormTests(TestCase):
    def test_aws_credentials_are_encrypted(self):
        form = CloudAccountForm(
            data={
                "name": "Production",
                "provider": CloudAccount.Provider.AWS,
                "aws_account_ref": "123456789012",
                "aws_regions": ["ap-northeast-1", "us-east-1"],
                "aws_access_key_id": "AKIA1234567890ABCDEF",
                "aws_secret_access_key": "secret-value",
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        account = form.save()

        self.assertNotIn("secret-value", account.encrypted_credentials)
        self.assertEqual(account.regions, ["ap-northeast-1", "us-east-1"])
        self.assertEqual(
            decrypt_json(account.encrypted_credentials)["aws_secret_access_key"],
            "secret-value",
        )

    def test_gcp_project_defaults_from_service_account(self):
        form = CloudAccountForm(
            data={
                "name": "GCP Prod",
                "provider": CloudAccount.Provider.GCP,
                "gcp_project_id": "",
                "gcp_locations": ["asia-northeast1"],
                "gcp_service_account_json": """
                {
                  "type": "service_account",
                  "project_id": "demo-project",
                  "client_email": "bot@demo-project.iam.gserviceaccount.com",
                  "private_key": "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\\n",
                  "token_uri": "https://oauth2.googleapis.com/token"
                }
                """,
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        account = form.save()

        self.assertEqual(account.account_ref, "demo-project")
        self.assertIn("bot@demo-project", account.credentials_hint)

    def test_markdown_filter_renders_headings_and_strips_scripts(self):
        html = render_markdown("# Briefing\n\n<script>alert(1)</script>\n\n- item")

        self.assertIn("<h1>Briefing</h1>", html)
        self.assertIn("<li>item</li>", html)
        self.assertNotIn("<script>", html)


class AuthFlowTests(TestCase):
    def test_first_visit_redirects_to_setup_when_no_users_exist(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("setup"))

    def test_setup_creates_owner_and_logs_in(self):
        response = self.client.post(
            reverse("setup"),
            data={
                "username": "owner",
                "email": "owner@example.com",
                "password1": "strong-test-pass-123",
                "password2": "strong-test-pass-123",
            },
        )

        self.assertEqual(response.status_code, 302)
        user = get_user_model().objects.get(username="owner")
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)


class DashboardTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="ops-admin",
            password="test-pass",
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_login(self.user)

    def test_dashboard_requires_login(self):
        self.client.logout()

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])

    def test_dashboard_loads(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "InfraLens AI")

    def test_demo_seed_creates_operational_data(self):
        response = self.client.post(reverse("demo_seed"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(CloudAccount.objects.count(), 1)
        self.assertGreater(Finding.objects.count(), 0)
        self.assertGreater(DailyBriefing.objects.count(), 0)
        self.assertTrue(
            AccountMembership.objects.filter(
                user=self.user,
                role=AccountMembership.Role.OWNER,
            ).exists()
        )

    def test_generate_daily_briefing_uses_findings(self):
        account = seed_demo_data()
        briefing = generate_daily_briefing(account, use_ai=False)

        self.assertIn("Daily Infra Briefing", briefing.body_markdown)
        self.assertIn("daily-export", briefing.body_markdown)

    def test_settings_page_loads(self):
        response = self.client.get(reverse("settings"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AI providers")

    def test_korean_fallback_briefing_uses_configured_language(self):
        GlobalSettings.load()
        GlobalSettings.objects.update(report_language=GlobalSettings.ReportLanguage.KO)
        account = seed_demo_data()

        briefing = generate_daily_briefing(account, use_ai=False)

        self.assertIn("제안 조치", briefing.body_markdown)
        self.assertEqual(briefing.evidence["report_language"], "ko")

    def test_non_member_cannot_see_cloud_account(self):
        account = seed_demo_data()
        user = get_user_model().objects.create_user(username="viewer", password="test-pass")
        self.client.force_login(user)

        response = self.client.get(reverse("dashboard"))

        self.assertNotContains(response, account.name)
        self.assertContains(response, "No cloud accounts yet")

    def test_member_can_see_cloud_account(self):
        account = seed_demo_data()
        user = get_user_model().objects.create_user(username="viewer", password="test-pass")
        AccountMembership.objects.create(
            user=user,
            account=account,
            role=AccountMembership.Role.VIEWER,
        )
        self.client.force_login(user)

        response = self.client.get(reverse("dashboard"))

        self.assertContains(response, account.name)


class WebhookTests(TestCase):
    def test_webhook_url_is_encrypted(self):
        user = get_user_model().objects.create_user(username="alice")
        form = WebhookEndpointForm(
            data={
                "name": "Slack",
                "provider": WebhookEndpoint.Provider.GENERIC,
                "webhook_url": "https://hooks.example.test/services/abc",
                "is_active": "on",
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        endpoint = form.save(user)

        self.assertNotIn("hooks.example", endpoint.encrypted_url)
        self.assertEqual(decrypt_text(endpoint.encrypted_url), "https://hooks.example.test/services/abc")


class CloudAccountEditDeleteTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="ops-admin",
            password="test-pass",
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_login(self.user)
        self.account = seed_demo_data()

    def test_edit_keeps_credentials_when_secret_blank(self):
        original = self.account.encrypted_credentials
        response = self.client.post(
            reverse("account_edit", args=[self.account.id]),
            data={
                "name": "Renamed Prod",
                "provider": CloudAccount.Provider.AWS,
                "aws_account_ref": "123456789012",
                "aws_regions": ["ap-northeast-1"],
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.account.refresh_from_db()
        self.assertEqual(self.account.name, "Renamed Prod")
        self.assertEqual(self.account.regions, ["ap-northeast-1"])
        # Untouched secret fields keep the stored credentials.
        self.assertEqual(self.account.encrypted_credentials, original)

    def test_edit_replaces_credentials_when_provided(self):
        response = self.client.post(
            reverse("account_edit", args=[self.account.id]),
            data={
                "name": "Demo AWS Production",
                "provider": CloudAccount.Provider.AWS,
                "aws_account_ref": "123456789012",
                "aws_regions": ["ap-northeast-1", "us-east-1"],
                "aws_access_key_id": "AKIANEWKEY1234567890",
                "aws_secret_access_key": "rotated-secret",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.account.refresh_from_db()
        self.assertEqual(
            decrypt_json(self.account.encrypted_credentials)["aws_secret_access_key"],
            "rotated-secret",
        )

    def test_delete_removes_account(self):
        response = self.client.post(reverse("account_delete", args=[self.account.id]))

        self.assertEqual(response.status_code, 302)
        self.assertFalse(CloudAccount.objects.filter(id=self.account.id).exists())

    def test_non_admin_cannot_delete(self):
        member = get_user_model().objects.create_user(username="viewer", password="test-pass")
        AccountMembership.objects.create(
            user=member,
            account=self.account,
            role=AccountMembership.Role.OPERATOR,
        )
        self.client.force_login(member)

        response = self.client.post(reverse("account_delete", args=[self.account.id]))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(CloudAccount.objects.filter(id=self.account.id).exists())


class AIProviderTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="ops-admin",
            password="test-pass",
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_login(self.user)

    def test_api_key_is_encrypted(self):
        form = AIProviderForm(
            data={
                "name": "Claude",
                "provider": AIProvider.Provider.ANTHROPIC,
                "model": "claude-opus-4-8",
                "api_key": "sk-ant-secret-key-value",
                "is_active": "on",
                "is_default": "on",
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        provider = form.save()

        self.assertNotIn("secret-key-value", provider.encrypted_api_key)
        self.assertEqual(decrypt_text(provider.encrypted_api_key), "sk-ant-secret-key-value")
        self.assertIn("...", provider.api_key_hint)

    def test_only_one_default_provider(self):
        first = AIProvider.objects.create(
            name="OpenAI", provider="openai", model="gpt-5.4-mini", is_default=True
        )
        second = AIProvider.objects.create(
            name="Gemini", provider="google", model="gemini-2.5-pro", is_default=True
        )

        first.refresh_from_db()
        self.assertFalse(first.is_default)
        self.assertTrue(second.is_default)
        self.assertEqual(AIProvider.get_default().pk, second.pk)

    def test_edit_keeps_key_when_blank(self):
        provider = AIProviderForm(
            data={
                "name": "OpenAI",
                "provider": "openai",
                "model": "gpt-5.4-mini",
                "api_key": "sk-original",
                "is_active": "on",
            }
        )
        self.assertTrue(provider.is_valid(), provider.errors)
        saved = provider.save()

        edit = AIProviderForm(
            data={
                "name": "OpenAI Prod",
                "provider": "openai",
                "model": "gpt-5.4",
                "api_key": "",
                "is_active": "on",
            },
            instance=saved,
        )
        self.assertTrue(edit.is_valid(), edit.errors)
        updated = edit.save()

        self.assertEqual(updated.model, "gpt-5.4")
        self.assertEqual(decrypt_text(updated.encrypted_api_key), "sk-original")
