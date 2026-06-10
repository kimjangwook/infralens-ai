from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from . import ai as ai_module
from .ai import (
    _extract_anthropic_text,
    _extract_google_text,
    _extract_openai_text,
    generate_ai_insight,
    verify_ai_provider,
)
from .crypto import decrypt_json, decrypt_text, encrypt_text
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

    def _member(self, username, role):
        user = get_user_model().objects.create_user(username=username, password="test-pass")
        AccountMembership.objects.create(user=user, account=self.account, role=role)
        return user

    def test_account_admin_can_edit_without_global_admin(self):
        admin = self._member("acct-admin", AccountMembership.Role.ADMIN)
        self.client.force_login(admin)

        response = self.client.post(
            reverse("account_edit", args=[self.account.id]),
            data={
                "name": "Edited By Account Admin",
                "provider": CloudAccount.Provider.AWS,
                "aws_account_ref": "123456789012",
                "aws_regions": ["ap-northeast-1"],
                "aws_access_key_id": "",
                "aws_secret_access_key": "",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.account.refresh_from_db()
        self.assertEqual(self.account.name, "Edited By Account Admin")

    def test_account_admin_cannot_delete(self):
        admin = self._member("acct-admin2", AccountMembership.Role.ADMIN)
        self.client.force_login(admin)

        response = self.client.post(reverse("account_delete", args=[self.account.id]))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(CloudAccount.objects.filter(id=self.account.id).exists())

    def test_account_owner_can_delete_without_global_admin(self):
        owner = self._member("acct-owner", AccountMembership.Role.OWNER)
        self.client.force_login(owner)

        response = self.client.post(reverse("account_delete", args=[self.account.id]))

        self.assertEqual(response.status_code, 302)
        self.assertFalse(CloudAccount.objects.filter(id=self.account.id).exists())

    def test_operator_cannot_edit(self):
        operator = self._member("acct-op", AccountMembership.Role.OPERATOR)
        self.client.force_login(operator)

        response = self.client.post(
            reverse("account_edit", args=[self.account.id]),
            data={
                "name": "Should Not Apply",
                "provider": CloudAccount.Provider.AWS,
                "aws_account_ref": "123456789012",
                "aws_regions": ["ap-northeast-1"],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.account.refresh_from_db()
        self.assertNotEqual(self.account.name, "Should Not Apply")


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


def _fake_response(payload: dict, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload
    response.text = ""
    if status >= 400:
        err = requests.HTTPError(response=response)
        response.raise_for_status.side_effect = err
    else:
        response.raise_for_status.return_value = None
    return response


class AIExtractTests(TestCase):
    def test_openai_output_text(self):
        self.assertEqual(_extract_openai_text({"output_text": "  hi  "}), "hi")

    def test_openai_structured_output(self):
        data = {"output": [{"content": [{"text": "a"}, {"text": "b"}]}]}
        self.assertEqual(_extract_openai_text(data), "a\nb")

    def test_anthropic_blocks(self):
        data = {"content": [{"type": "text", "text": "claude says"}]}
        self.assertEqual(_extract_anthropic_text(data), "claude says")

    def test_google_candidates(self):
        data = {"candidates": [{"content": {"parts": [{"text": "gemini says"}]}}]}
        self.assertEqual(_extract_google_text(data), "gemini says")


class AIDispatchTests(TestCase):
    def setUp(self):
        # Migration 0005 can seed a provider from a real OPENAI_API_KEY in the
        # environment. Clear it so dispatch tests are deterministic and never
        # make a live API call.
        AIProvider.objects.all().delete()

    def _provider(self, provider, model, key="sk-test-key-12345", **kwargs):
        return AIProvider.objects.create(
            name=f"{provider}-prov",
            provider=provider,
            model=model,
            encrypted_api_key=encrypt_text(key),
            is_active=True,
            is_default=kwargs.get("is_default", True),
        )

    def test_openai_dispatch_uses_responses_api(self):
        self._provider(AIProvider.Provider.OPENAI, "gpt-5.5")
        with patch.object(ai_module.requests, "post", return_value=_fake_response({"output_text": "OK"})) as mock_post:
            text, meta = generate_ai_insight(title_account="Acct", findings=[], report_language="en")

        self.assertEqual(text, "OK")
        self.assertEqual(meta["ai_status"], "generated")
        url = mock_post.call_args.args[0]
        headers = mock_post.call_args.kwargs["headers"]
        self.assertIn("api.openai.com/v1/responses", url)
        self.assertEqual(headers["Authorization"], "Bearer sk-test-key-12345")

    def test_anthropic_dispatch_uses_messages_api(self):
        self._provider(AIProvider.Provider.ANTHROPIC, "claude-opus-4-8")
        with patch.object(ai_module.requests, "post", return_value=_fake_response({"content": [{"text": "OK"}]})) as mock_post:
            text, meta = generate_ai_insight(title_account="Acct", findings=[], report_language="en")

        self.assertEqual(text, "OK")
        url = mock_post.call_args.args[0]
        headers = mock_post.call_args.kwargs["headers"]
        self.assertIn("api.anthropic.com/v1/messages", url)
        self.assertEqual(headers["x-api-key"], "sk-test-key-12345")
        self.assertIn("anthropic-version", headers)

    def test_google_dispatch_uses_generatecontent(self):
        self._provider(AIProvider.Provider.GOOGLE, "gemini-3.5-flash")
        with patch.object(ai_module.requests, "post", return_value=_fake_response({"candidates": [{"content": {"parts": [{"text": "OK"}]}}]})) as mock_post:
            text, meta = generate_ai_insight(title_account="Acct", findings=[], report_language="en")

        self.assertEqual(text, "OK")
        url = mock_post.call_args.args[0]
        headers = mock_post.call_args.kwargs["headers"]
        self.assertIn("models/gemini-3.5-flash:generateContent", url)
        self.assertEqual(headers["x-goog-api-key"], "sk-test-key-12345")

    @override_settings(AI_ENABLED=False)
    def test_disabled_short_circuits(self):
        self._provider(AIProvider.Provider.OPENAI, "gpt-5.5")
        text, meta = generate_ai_insight(title_account="A", findings=[], report_language="en")
        self.assertIsNone(text)
        self.assertEqual(meta["ai_status"], "disabled")

    def test_no_provider_configured(self):
        text, meta = generate_ai_insight(title_account="A", findings=[], report_language="en")
        self.assertIsNone(text)
        self.assertEqual(meta["ai_status"], "no_provider")

    def test_missing_api_key(self):
        AIProvider.objects.create(
            name="empty", provider=AIProvider.Provider.OPENAI, model="gpt-5.5",
            encrypted_api_key="", is_active=True, is_default=True,
        )
        text, meta = generate_ai_insight(title_account="A", findings=[], report_language="en")
        self.assertIsNone(text)
        self.assertEqual(meta["ai_status"], "missing_api_key")

    def test_request_failure_is_reported(self):
        self._provider(AIProvider.Provider.OPENAI, "gpt-5.5")
        with patch.object(ai_module.requests, "post", side_effect=requests.ConnectionError("boom")):
            text, meta = generate_ai_insight(title_account="A", findings=[], report_language="en")
        self.assertIsNone(text)
        self.assertEqual(meta["ai_status"], "request_failed")


class AIProviderVerifyTests(TestCase):
    def setUp(self):
        AIProvider.objects.all().delete()
        self.user = get_user_model().objects.create_user(
            username="admin", password="x", is_staff=True, is_superuser=True
        )
        self.client.force_login(self.user)
        self.provider = AIProvider.objects.create(
            name="OpenAI", provider=AIProvider.Provider.OPENAI, model="gpt-5.5",
            encrypted_api_key=encrypt_text("sk-key"), is_active=True, is_default=True,
        )

    def test_verify_success(self):
        with patch.object(ai_module.requests, "post", return_value=_fake_response({"output_text": "OK"})):
            ok, message = verify_ai_provider(self.provider)
        self.assertTrue(ok)
        self.assertIn("OK", message)

    def test_verify_http_error(self):
        with patch.object(ai_module.requests, "post", return_value=_fake_response({}, status=401)):
            ok, message = verify_ai_provider(self.provider)
        self.assertFalse(ok)
        self.assertIn("401", message)

    def test_test_button_view_success(self):
        with patch.object(ai_module.requests, "post", return_value=_fake_response({"output_text": "OK"})):
            response = self.client.post(reverse("ai_provider_test", args=[self.provider.id]))
        self.assertEqual(response.status_code, 302)

    def test_test_button_view_requires_global_admin(self):
        member = get_user_model().objects.create_user(username="plain", password="x")
        self.client.force_login(member)
        response = self.client.post(reverse("ai_provider_test", args=[self.provider.id]))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("dashboard"), response["Location"])


class TopologyTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def test_schedule_edge_matches_resource_by_provider_id(self):
        from .topology import build_topology, render_mermaid

        graph = build_topology([self.account])

        self.assertGreaterEqual(len(graph.edges), 1)
        mermaid = render_mermaid(graph)
        self.assertIn("flowchart LR", mermaid)
        self.assertIn("daily-export", mermaid)

    def test_orphan_schedule_detected(self):
        from .models import Schedule
        from .topology import build_topology

        Schedule.objects.create(
            account=self.account,
            provider_id="arn:aws:events:us-east-1:123456789012:rule/ghost",
            name="ghost-rule",
            target_type="aws.lambda",
            target_ref="arn:aws:lambda:us-east-1:123456789012:function:missing",
        )

        graph = build_topology([self.account])

        self.assertEqual(len(graph.orphan_schedules), 1)
        self.assertEqual(graph.orphan_schedules[0].name, "ghost-rule")

    def test_untriggered_resource_detected(self):
        from .models import Resource
        from .topology import build_topology

        Resource.objects.create(
            account=self.account,
            provider_id="arn:aws:lambda:ap-northeast-1:123456789012:function:idle",
            resource_type="aws.lambda",
            name="idle",
        )

        graph = build_topology([self.account])

        self.assertIn("idle", [resource.name for resource in graph.untriggered_resources])

    def test_hotspot_detected(self):
        from .models import Schedule
        from .topology import build_topology

        target = "arn:aws:lambda:ap-northeast-1:123456789012:function:daily-export"
        for index in range(2):
            Schedule.objects.create(
                account=self.account,
                provider_id=f"arn:aws:events:ap-northeast-1:123456789012:rule/extra-{index}",
                name=f"extra-{index}",
                target_type="aws.lambda",
                target_ref=target,
            )

        graph = build_topology([self.account])

        self.assertEqual(len(graph.hotspots), 1)
        self.assertEqual(graph.hotspots[0][1], 3)

    def test_analyze_topology_creates_findings(self):
        from .models import Schedule, ScanRun
        from .topology import analyze_topology

        Schedule.objects.create(
            account=self.account,
            provider_id="arn:aws:events:us-east-1:123456789012:rule/ghost",
            name="ghost-rule",
            target_type="aws.lambda",
            target_ref="arn:aws:lambda:us-east-1:123456789012:function:missing",
        )
        scan_run = ScanRun.objects.create(account=self.account)

        created = analyze_topology(self.account, scan_run)

        self.assertGreaterEqual(created, 1)
        self.assertTrue(
            Finding.objects.filter(account=self.account, category="topology").exists()
        )

    def test_topology_page_loads(self):
        user = get_user_model().objects.create_user(
            username="topo-admin", password="x", is_staff=True, is_superuser=True
        )
        self.client.force_login(user)

        response = self.client.get(reverse("topology"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "flowchart LR")


class ScanScheduleTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def test_is_due_logic(self):
        from datetime import timedelta

        from django.utils import timezone

        from .models import ScanSchedule

        schedule = ScanSchedule.objects.create(account=self.account)
        self.assertTrue(schedule.is_due())

        schedule.next_run_at = timezone.now() + timedelta(hours=1)
        self.assertFalse(schedule.is_due())

        schedule.next_run_at = timezone.now() - timedelta(minutes=1)
        self.assertTrue(schedule.is_due())

        schedule.enabled = False
        self.assertFalse(schedule.is_due())

    def test_mark_ran_advances_next_run(self):
        from datetime import timedelta

        from django.utils import timezone

        from .models import ScanSchedule

        schedule = ScanSchedule.objects.create(
            account=self.account,
            interval_minutes=ScanSchedule.Interval.HOURLY,
        )
        before = timezone.now()

        schedule.mark_ran("success")

        self.assertEqual(schedule.last_status, "success")
        self.assertGreaterEqual(schedule.next_run_at, before + timedelta(minutes=59))

    def test_run_scheduler_command_executes_due_schedules(self):
        from io import StringIO

        from django.core.management import call_command

        from .models import ScanRun, ScanSchedule

        ScanSchedule.objects.create(account=self.account)
        fake_run = ScanRun.objects.create(
            account=self.account, status=ScanRun.Status.SUCCESS
        )
        out = StringIO()
        with patch(
            "ops.management.commands.run_scheduler.run_scan_pipeline",
            return_value=fake_run,
        ) as mock_pipeline:
            call_command("run_scheduler", stdout=out)

        mock_pipeline.assert_called_once()
        schedule = ScanSchedule.objects.get(account=self.account)
        self.assertEqual(schedule.last_status, ScanRun.Status.SUCCESS)
        self.assertIsNotNone(schedule.next_run_at)

    def test_schedule_update_view_requires_admin(self):
        viewer = get_user_model().objects.create_user(username="sched-viewer", password="x")
        AccountMembership.objects.create(
            user=viewer, account=self.account, role=AccountMembership.Role.OPERATOR
        )
        self.client.force_login(viewer)

        response = self.client.post(
            reverse("account_schedule_update", args=[self.account.id]),
            data={"enabled": "on", "interval_minutes": 60},
        )

        self.assertEqual(response.status_code, 302)
        from .models import ScanSchedule

        self.assertFalse(ScanSchedule.objects.filter(account=self.account, enabled=True).exists())

    def test_schedule_update_view_saves_and_sets_due(self):
        admin = get_user_model().objects.create_user(
            username="sched-admin", password="x", is_staff=True, is_superuser=True
        )
        self.client.force_login(admin)

        response = self.client.post(
            reverse("account_schedule_update", args=[self.account.id]),
            data={"enabled": "on", "interval_minutes": 360},
        )

        self.assertEqual(response.status_code, 302)
        from .models import ScanSchedule

        schedule = ScanSchedule.objects.get(account=self.account)
        self.assertTrue(schedule.enabled)
        self.assertEqual(schedule.interval_minutes, 360)
        self.assertIsNotNone(schedule.next_run_at)


class WebhookTriggerTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def test_invalid_token_rejected(self):
        response = self.client.post(
            reverse("webhook_scan_trigger", args=[self.account.id, "wrong-token"])
        )

        self.assertEqual(response.status_code, 403)

    def test_get_not_allowed(self):
        response = self.client.get(
            reverse("webhook_scan_trigger", args=[self.account.id, self.account.webhook_token])
        )

        self.assertEqual(response.status_code, 405)

    def test_valid_token_triggers_pipeline(self):
        from .models import ScanRun

        fake_run = ScanRun.objects.create(
            account=self.account,
            status=ScanRun.Status.SUCCESS,
            summary={"resources": 1},
        )
        with patch("ops.views.run_scan_pipeline", return_value=fake_run) as mock_pipeline:
            response = self.client.post(
                reverse(
                    "webhook_scan_trigger",
                    args=[self.account.id, self.account.webhook_token],
                )
            )

        self.assertEqual(response.status_code, 200)
        mock_pipeline.assert_called_once_with(self.account)
        self.assertEqual(response.json()["status"], ScanRun.Status.SUCCESS)

    def test_failed_scan_returns_502(self):
        from .models import ScanRun

        fake_run = ScanRun.objects.create(
            account=self.account,
            status=ScanRun.Status.FAILED,
            error_message="credentials expired",
        )
        with patch("ops.views.run_scan_pipeline", return_value=fake_run):
            response = self.client.post(
                reverse(
                    "webhook_scan_trigger",
                    args=[self.account.id, self.account.webhook_token],
                )
            )

        self.assertEqual(response.status_code, 502)
        self.assertIn("credentials expired", response.json()["error"])

    def test_token_rotation_changes_url(self):
        admin = get_user_model().objects.create_user(
            username="rotator", password="x", is_staff=True, is_superuser=True
        )
        self.client.force_login(admin)
        old_token = self.account.webhook_token

        response = self.client.post(
            reverse("account_token_regenerate", args=[self.account.id])
        )

        self.assertEqual(response.status_code, 302)
        self.account.refresh_from_db()
        self.assertNotEqual(self.account.webhook_token, old_token)

    def test_existing_accounts_get_distinct_tokens(self):
        other = CloudAccount.objects.create(
            name="Second", provider=CloudAccount.Provider.AWS, account_ref="2"
        )
        self.assertNotEqual(self.account.webhook_token, other.webhook_token)
        self.assertGreaterEqual(len(other.webhook_token), 20)


@override_settings(AI_ENABLED=False)
class RemediationProposalTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()
        self.finding = Finding.objects.filter(account=self.account).first()
        self.admin = get_user_model().objects.create_user(
            username="fixer", password="x", is_staff=True, is_superuser=True
        )

    def test_fallback_proposal_created_when_ai_disabled(self):
        from .models import RemediationProposal
        from .services import create_remediation_proposal

        proposal = create_remediation_proposal(self.finding, requested_by=self.admin)

        self.assertEqual(proposal.status, RemediationProposal.Status.FALLBACK)
        self.assertIn(self.finding.title, proposal.body_markdown)
        self.assertEqual(proposal.ai_meta["ai_status"], "disabled")

    def test_fallback_uses_korean_when_configured(self):
        GlobalSettings.load()
        GlobalSettings.objects.update(report_language=GlobalSettings.ReportLanguage.KO)
        from .services import create_remediation_proposal

        proposal = create_remediation_proposal(self.finding)

        self.assertIn("수정 제안", proposal.body_markdown)

    def test_propose_view_creates_and_displays_proposal(self):
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("finding_propose_fix", args=[self.finding.id])
        )

        self.assertEqual(response.status_code, 302)
        detail = self.client.get(reverse("finding_detail", args=[self.finding.id]))
        self.assertContains(detail, "Template fallback")

    def test_viewer_cannot_propose(self):
        viewer = get_user_model().objects.create_user(username="ro-viewer", password="x")
        AccountMembership.objects.create(
            user=viewer, account=self.account, role=AccountMembership.Role.VIEWER
        )
        self.client.force_login(viewer)

        response = self.client.post(
            reverse("finding_propose_fix", args=[self.finding.id])
        )

        self.assertEqual(response.status_code, 302)
        from .models import RemediationProposal

        self.assertEqual(RemediationProposal.objects.count(), 0)

    def test_ai_generated_proposal(self):
        with override_settings(AI_ENABLED=True):
            AIProvider.objects.all().delete()
            AIProvider.objects.create(
                name="OpenAI",
                provider=AIProvider.Provider.OPENAI,
                model="gpt-5.5",
                encrypted_api_key=encrypt_text("sk-test"),
                is_active=True,
                is_default=True,
            )
            from .models import RemediationProposal
            from .services import create_remediation_proposal

            with patch.object(
                ai_module.requests,
                "post",
                return_value=_fake_response({"output_text": "## Root cause hypothesis\nDisk full."}),
            ):
                proposal = create_remediation_proposal(self.finding, requested_by=self.admin)

            self.assertEqual(proposal.status, RemediationProposal.Status.GENERATED)
            self.assertIn("Root cause", proposal.body_markdown)


class S3ExposureTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def _client(self, is_public=False, pab_code=None, pab=None):
        from botocore.exceptions import ClientError

        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "data-bucket"}]}
        client.get_bucket_policy_status.return_value = {
            "PolicyStatus": {"IsPublic": is_public}
        }
        if pab_code:
            client.get_public_access_block.side_effect = ClientError(
                {"Error": {"Code": pab_code}}, "GetPublicAccessBlock"
            )
        else:
            client.get_public_access_block.return_value = {
                "PublicAccessBlockConfiguration": pab
                or {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        return client

    def _run(self, client):
        from .models import ScanRun
        from .scanners import aws as aws_module
        from .scanners.common import UpsertCounter

        scan_run = ScanRun.objects.create(account=self.account)
        session = MagicMock()
        session.client.return_value = client
        with patch.object(aws_module, "_session", return_value=session):
            aws_module._scan_s3_exposure(self.account, {}, scan_run, UpsertCounter())

    def test_public_bucket_is_critical(self):
        self._run(self._client(is_public=True))

        finding = Finding.objects.get(category="exposure", severity=Finding.Severity.CRITICAL)
        self.assertIn("data-bucket", finding.title)

    def test_missing_public_access_block_is_warning(self):
        self._run(self._client(pab_code="NoSuchPublicAccessBlockConfiguration"))

        finding = Finding.objects.get(category="exposure", severity=Finding.Severity.WARNING)
        self.assertIn("public access block", finding.title)

    def test_locked_down_bucket_creates_no_finding(self):
        self._run(self._client())

        self.assertFalse(
            Finding.objects.filter(category="exposure").exclude(
                severity=Finding.Severity.INFO
            ).exists()
        )
        self.assertTrue(
            self.account.resources.filter(resource_type="aws.s3_bucket").exists()
        )


class GCSExposureTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def _fake_session(self, bindings, prevention="enforced"):
        def fake_get(url, timeout=20):
            response = MagicMock()
            response.status_code = 200
            response.raise_for_status.return_value = None
            if url.endswith("/iam"):
                response.json.return_value = {"bindings": bindings}
            else:
                response.json.return_value = {
                    "items": [
                        {
                            "name": "assets",
                            "location": "ASIA-NORTHEAST1",
                            "storageClass": "STANDARD",
                            "iamConfiguration": {"publicAccessPrevention": prevention},
                        }
                    ]
                }
            return response

        session = MagicMock()
        session.get.side_effect = fake_get
        return session

    def test_public_binding_is_critical(self):
        from .models import ScanRun
        from .scanners import gcp as gcp_module
        from .scanners.common import UpsertCounter

        scan_run = ScanRun.objects.create(account=self.account)
        session = self._fake_session(
            [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]
        )
        gcp_module._scan_gcs_exposure(self.account, session, "proj", scan_run, UpsertCounter())

        finding = Finding.objects.get(category="exposure", severity=Finding.Severity.CRITICAL)
        self.assertIn("assets", finding.title)

    def test_unenforced_prevention_is_warning(self):
        from .models import ScanRun
        from .scanners import gcp as gcp_module
        from .scanners.common import UpsertCounter

        scan_run = ScanRun.objects.create(account=self.account)
        session = self._fake_session([], prevention="inherited")
        gcp_module._scan_gcs_exposure(self.account, session, "proj", scan_run, UpsertCounter())

        self.assertTrue(
            Finding.objects.filter(
                category="exposure", severity=Finding.Severity.WARNING
            ).exists()
        )


class ChangeDiffTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()
        from django.utils import timezone

        self.account.last_scan_at = timezone.now()
        self.account.save(update_fields=["last_scan_at"])

    def test_removed_and_added_resources_are_reported(self):
        from datetime import timedelta

        from django.utils import timezone

        from .models import Resource, ScanRun
        from .scanners.base import _apply_change_diff

        stale = Resource.objects.create(
            account=self.account,
            provider_id="arn:aws:lambda:ap-northeast-1:1:function:gone",
            resource_type="aws.lambda",
            name="gone",
            last_seen_at=timezone.now() - timedelta(days=2),
        )
        previous = {stale.provider_id: "gone"}
        scan_run = ScanRun.objects.create(account=self.account)
        scan_run.mark_running()
        # Simulate the scanner refreshing the surviving resource during the scan.
        self.account.resources.filter(name="daily-export").update(
            last_seen_at=timezone.now()
        )

        changes = _apply_change_diff(self.account, scan_run, True, previous, {})

        self.assertIn("gone", changes["resources_removed"])
        self.assertIn("daily-export", changes["resources_added"])
        self.assertFalse(Resource.objects.filter(id=stale.id).exists())
        self.assertTrue(Finding.objects.filter(category="change").exists())


class WebhookProviderTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def test_slack_payload_shape(self):
        from .models import ScanRun
        from .services import _slack_payload

        scan_run = ScanRun.objects.create(account=self.account)
        findings = list(Finding.objects.filter(account=self.account))

        payload = _slack_payload(scan_run, findings)

        self.assertIn("blocks", payload)
        self.assertEqual(payload["blocks"][0]["type"], "header")
        self.assertIn("InfraLens", payload["text"])

    def test_notion_payload_uses_parent_page(self):
        from .models import ScanRun
        from .services import _notion_payload

        user = get_user_model().objects.create_user(username="notion-user")
        endpoint = WebhookEndpoint.objects.create(
            user=user,
            name="Notion",
            provider=WebhookEndpoint.Provider.NOTION,
            encrypted_url=encrypt_text("secret_token"),
            config={"notion_parent_page_id": "page-123"},
        )
        scan_run = ScanRun.objects.create(account=self.account)
        findings = list(Finding.objects.filter(account=self.account))

        payload = _notion_payload(endpoint, scan_run, findings)

        self.assertEqual(payload["parent"]["page_id"], "page-123")
        self.assertGreaterEqual(len(payload["children"]), 1)

    def test_notion_form_requires_parent_page(self):
        form = WebhookEndpointForm(
            data={
                "name": "Notion",
                "provider": WebhookEndpoint.Provider.NOTION,
                "webhook_url": "secret_abc",
                "is_active": "on",
            }
        )
        self.assertFalse(form.is_valid())

        form = WebhookEndpointForm(
            data={
                "name": "Notion",
                "provider": WebhookEndpoint.Provider.NOTION,
                "webhook_url": "secret_abc",
                "notion_parent_page_id": "page-1",
                "is_active": "on",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)


class CustomRuleTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def test_metadata_rule_matches_resource(self):
        from .models import CustomRule, ScanRun
        from .rules import evaluate_custom_rules

        CustomRule.objects.create(
            name="Long Lambda timeout",
            target=CustomRule.Target.RESOURCE,
            field_path="metadata.timeout",
            operator=CustomRule.Operator.GT,
            value="30",
            severity=Finding.Severity.WARNING,
            suggested_action="Lower the timeout.",
        )
        scan_run = ScanRun.objects.create(account=self.account)

        created = evaluate_custom_rules(self.account, scan_run)

        self.assertEqual(created, 1)
        finding = Finding.objects.get(category="custom")
        self.assertIn("Long Lambda timeout", finding.title)
        self.assertIn("daily-export", finding.title)

    def test_rule_scoped_to_other_account_is_skipped(self):
        from .models import CustomRule, ScanRun
        from .rules import evaluate_custom_rules

        other = CloudAccount.objects.create(
            name="Other", provider=CloudAccount.Provider.AWS, account_ref="999"
        )
        CustomRule.objects.create(
            name="Scoped",
            account=other,
            target=CustomRule.Target.RESOURCE,
            field_path="name",
            operator=CustomRule.Operator.CONTAINS,
            value="daily",
        )
        scan_run = ScanRun.objects.create(account=self.account)

        self.assertEqual(evaluate_custom_rules(self.account, scan_run), 0)

    def test_regex_operator(self):
        from .rules import _matches
        from .models import CustomRule

        self.assertTrue(_matches(CustomRule.Operator.REGEX, "daily-export", r"^daily-"))
        self.assertFalse(_matches(CustomRule.Operator.REGEX, "daily-export", r"["))


class ResourceDetailViewTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()
        self.user = get_user_model().objects.create_user(
            username="res-admin", password="x", is_staff=True, is_superuser=True
        )
        self.client.force_login(self.user)

    def test_resource_page_shows_related_findings(self):
        resource = self.account.resources.get(name="daily-export")

        response = self.client.get(reverse("resource_detail", args=[resource.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "daily-export")
        self.assertContains(response, "Inbound schedules")

    def test_non_member_cannot_view_resource(self):
        outsider = get_user_model().objects.create_user(username="outsider", password="x")
        self.client.force_login(outsider)
        resource = self.account.resources.first()

        response = self.client.get(reverse("resource_detail", args=[resource.id]))

        self.assertEqual(response.status_code, 404)


class BillingExportValidationTests(TestCase):
    def test_invalid_table_id_creates_info_finding(self):
        from .models import ScanRun
        from .scanners import gcp as gcp_module
        from .scanners.common import UpsertCounter

        account = seed_demo_data()
        scan_run = ScanRun.objects.create(account=account)
        session = MagicMock()

        gcp_module._scan_billing_export(
            account, session, "proj", "bad table; DROP", scan_run, UpsertCounter()
        )

        session.post.assert_not_called()
        self.assertTrue(
            Finding.objects.filter(title="GCP billing export table id is invalid").exists()
        )


class BackgroundJobTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def test_claim_and_process_scan_job(self):
        from .models import BackgroundJob, ScanRun
        from .services import claim_next_job, enqueue_scan, process_job
        from . import services as services_module

        enqueue_scan(self.account)
        job = claim_next_job()
        self.assertIsNotNone(job)
        self.assertEqual(job.status, BackgroundJob.Status.RUNNING)
        # A second claim finds nothing while the first is running.
        self.assertIsNone(claim_next_job())

        fake_run = ScanRun.objects.create(
            account=self.account, status=ScanRun.Status.SUCCESS
        )
        with patch.object(services_module, "run_scan_pipeline", return_value=fake_run):
            process_job(job)

        job.refresh_from_db()
        self.assertEqual(job.status, BackgroundJob.Status.DONE)
        self.assertEqual(job.result["status"], ScanRun.Status.SUCCESS)

    def test_failed_scan_marks_job_failed(self):
        from .models import BackgroundJob, ScanRun
        from .services import claim_next_job, enqueue_scan, process_job
        from . import services as services_module

        enqueue_scan(self.account)
        job = claim_next_job()
        fake_run = ScanRun.objects.create(
            account=self.account,
            status=ScanRun.Status.FAILED,
            error_message="expired credentials",
        )
        with patch.object(services_module, "run_scan_pipeline", return_value=fake_run):
            process_job(job)

        job.refresh_from_db()
        self.assertEqual(job.status, BackgroundJob.Status.FAILED)
        self.assertIn("expired", job.error_message)

    @override_settings(ASYNC_SCANS=True)
    def test_webhook_trigger_enqueues_when_async(self):
        from .models import BackgroundJob

        response = self.client.post(
            reverse(
                "webhook_scan_trigger",
                args=[self.account.id, self.account.webhook_token],
            )
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(BackgroundJob.objects.count(), 1)


@override_settings(AI_ENABLED=False)
class DailyReportTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()

    def test_report_generated_once_per_day_after_hour(self):
        from datetime import datetime, timezone as dt_timezone

        from .services import maybe_generate_daily_report

        GlobalSettings.load()
        GlobalSettings.objects.update(daily_report_enabled=True, daily_report_hour=9)

        early = datetime(2026, 6, 10, 7, 0, tzinfo=dt_timezone.utc)
        self.assertIsNone(maybe_generate_daily_report(early))

        due = datetime(2026, 6, 10, 10, 0, tzinfo=dt_timezone.utc)
        briefing = maybe_generate_daily_report(due)
        self.assertIsNotNone(briefing)
        self.assertIsNone(briefing.account)

        # Second call the same day is a no-op.
        self.assertIsNone(maybe_generate_daily_report(due))

    def test_disabled_report_never_generates(self):
        from datetime import datetime, timezone as dt_timezone

        from .services import maybe_generate_daily_report

        due = datetime(2026, 6, 10, 23, 0, tzinfo=dt_timezone.utc)
        self.assertIsNone(maybe_generate_daily_report(due))

    def test_dispatch_sends_to_flagged_endpoints(self):
        from . import services as services_module
        from .services import dispatch_daily_report, generate_daily_briefing

        user = get_user_model().objects.create_user(username="report-user")
        WebhookEndpoint.objects.create(
            user=user,
            name="Reports",
            encrypted_url=encrypt_text("https://hooks.example.test/report"),
            receive_daily_report=True,
        )
        WebhookEndpoint.objects.create(
            user=user,
            name="No reports",
            encrypted_url=encrypt_text("https://hooks.example.test/other"),
            receive_daily_report=False,
        )
        briefing = generate_daily_briefing(None, use_ai=False)

        with patch.object(
            services_module.requests, "post", return_value=_fake_response({})
        ) as mock_post:
            delivered = dispatch_daily_report(briefing)

        self.assertEqual(delivered, 1)
        self.assertEqual(mock_post.call_count, 1)


class GitHubIssueTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()
        self.finding = Finding.objects.filter(account=self.account).first()
        self.admin = get_user_model().objects.create_user(
            username="gh-admin", password="x", is_staff=True, is_superuser=True
        )
        self.client.force_login(self.admin)

    def test_requires_configuration(self):
        from .services import create_github_issue

        ok, message = create_github_issue(self.finding)

        self.assertFalse(ok)
        self.assertIn("Settings", message)

    def test_creates_issue_and_stores_url(self):
        from . import services as services_module
        from .services import create_github_issue

        settings_obj = GlobalSettings.load()
        settings_obj.github_repo = "owner/repo"
        settings_obj.encrypted_github_token = encrypt_text("ghp_test")
        settings_obj.save()

        with patch.object(
            services_module.requests,
            "post",
            return_value=_fake_response({"html_url": "https://github.com/owner/repo/issues/1"}),
        ) as mock_post:
            ok, url = create_github_issue(self.finding)

        self.assertTrue(ok)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.github_issue_url, url)
        called_url = mock_post.call_args.args[0]
        self.assertIn("repos/owner/repo/issues", called_url)

    def test_view_requires_operator(self):
        viewer = get_user_model().objects.create_user(username="gh-viewer", password="x")
        AccountMembership.objects.create(
            user=viewer, account=self.account, role=AccountMembership.Role.VIEWER
        )
        self.client.force_login(viewer)

        response = self.client.post(
            reverse("finding_github_issue", args=[self.finding.id])
        )

        self.assertEqual(response.status_code, 302)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.github_issue_url, "")


class MetricsTests(TestCase):
    def test_disabled_without_token(self):
        response = self.client.get(reverse("metrics"))
        self.assertEqual(response.status_code, 404)

    @override_settings(METRICS_TOKEN="metrics-secret")
    def test_wrong_token_rejected(self):
        response = self.client.get(reverse("metrics"), {"token": "nope"})
        self.assertEqual(response.status_code, 403)

    @override_settings(METRICS_TOKEN="metrics-secret")
    def test_metrics_exposed_with_token(self):
        seed_demo_data()

        response = self.client.get(reverse("metrics"), {"token": "metrics-secret"})

        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("infralens_accounts 1", body)
        self.assertIn('infralens_open_findings{severity="warning"}', body)


class IamEdgeTests(TestCase):
    def test_lambda_role_becomes_iam_node(self):
        from .models import Resource
        from .topology import build_topology, render_mermaid

        account = seed_demo_data()
        Resource.objects.filter(account=account, name="daily-export").update(
            metadata={
                "runtime": "python3.12",
                "iam_role": "arn:aws:iam::123456789012:role/daily-export-role",
            }
        )

        graph = build_topology([account])

        iam_nodes = [node for node in graph.nodes if node.kind == "iam"]
        self.assertEqual(len(iam_nodes), 1)
        self.assertEqual(iam_nodes[0].label, "daily-export-role")
        self.assertIn("daily-export-role", render_mermaid(graph))


class PlanLimitTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(
            username="plan-admin", password="x", is_staff=True, is_superuser=True
        )
        self.client.force_login(self.admin)

    def test_free_plan_blocks_third_account(self):
        from .billing import can_add_account

        CloudAccount.objects.create(name="A", provider="aws", account_ref="1")
        self.assertTrue(can_add_account())
        CloudAccount.objects.create(name="B", provider="aws", account_ref="2")
        self.assertFalse(can_add_account())

        response = self.client.get(reverse("account_create"))
        self.assertEqual(response.status_code, 302)

    def test_expired_paid_plan_falls_back_to_free(self):
        from datetime import date, timedelta

        from .billing import effective_plan

        settings_obj = GlobalSettings.load()
        settings_obj.plan = GlobalSettings.Plan.PRO
        settings_obj.plan_valid_until = date.today() - timedelta(days=1)
        settings_obj.save()

        self.assertEqual(effective_plan(), GlobalSettings.Plan.FREE)

        settings_obj.plan_valid_until = date.today() + timedelta(days=30)
        settings_obj.save()
        self.assertEqual(effective_plan(), GlobalSettings.Plan.PRO)

    def test_usage_recording_increments(self):
        from .billing import record_usage, usage_today
        from .models import UsageRecord

        record_usage(UsageRecord.Kind.SCAN)
        record_usage(UsageRecord.Kind.SCAN, 2)

        self.assertEqual(usage_today(UsageRecord.Kind.SCAN), 3)


class StripeWebhookTests(TestCase):
    def _signed(self, payload: bytes, secret: str) -> str:
        import hashlib
        import hmac as hmac_lib
        import time as time_lib

        timestamp = str(int(time_lib.time()))
        mac = hmac_lib.new(
            secret.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256
        ).hexdigest()
        return f"t={timestamp},v1={mac}"

    def test_disabled_without_secret(self):
        response = self.client.post(
            reverse("stripe_webhook"), data=b"{}", content_type="application/json"
        )
        self.assertEqual(response.status_code, 404)

    @override_settings(STRIPE_WEBHOOK_SECRET="whsec_test")
    def test_invalid_signature_rejected(self):
        response = self.client.post(
            reverse("stripe_webhook"),
            data=b"{}",
            content_type="application/json",
            HTTP_STRIPE_SIGNATURE="t=1,v1=bad",
        )
        self.assertEqual(response.status_code, 400)

    @override_settings(STRIPE_WEBHOOK_SECRET="whsec_test")
    def test_checkout_completed_activates_plan(self):
        import json as json_lib

        payload = json_lib.dumps(
            {
                "type": "checkout.session.completed",
                "data": {
                    "object": {
                        "metadata": {"infralens_plan": "pro"},
                        "customer": "cus_123",
                    }
                },
            }
        ).encode()

        response = self.client.post(
            reverse("stripe_webhook"),
            data=payload,
            content_type="application/json",
            HTTP_STRIPE_SIGNATURE=self._signed(payload, "whsec_test"),
        )

        self.assertEqual(response.status_code, 200)
        settings_obj = GlobalSettings.load()
        self.assertEqual(settings_obj.plan, GlobalSettings.Plan.PRO)
        self.assertEqual(settings_obj.stripe_customer_id, "cus_123")

    @override_settings(STRIPE_WEBHOOK_SECRET="whsec_test")
    def test_subscription_deleted_reverts_to_free(self):
        import json as json_lib

        settings_obj = GlobalSettings.load()
        settings_obj.plan = GlobalSettings.Plan.TEAM
        settings_obj.save()

        payload = json_lib.dumps(
            {"type": "customer.subscription.deleted", "data": {"object": {}}}
        ).encode()
        response = self.client.post(
            reverse("stripe_webhook"),
            data=payload,
            content_type="application/json",
            HTTP_STRIPE_SIGNATURE=self._signed(payload, "whsec_test"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(GlobalSettings.load().plan, GlobalSettings.Plan.FREE)


class InvitationTests(TestCase):
    def setUp(self):
        self.account = seed_demo_data()
        self.admin = get_user_model().objects.create_user(
            username="invite-admin", password="x", is_staff=True, is_superuser=True
        )
        self.client.force_login(self.admin)

    def _create_invitation(self):
        from .forms import InvitationForm

        form = InvitationForm(
            data={
                "note": "Welcome",
                "role": AccountMembership.Role.OPERATOR,
                "invite_accounts": [str(self.account.id)],
            },
            accounts=CloudAccount.objects.all(),
        )
        self.assertTrue(form.is_valid(), form.errors)
        return form.save(self.admin)

    def test_accept_creates_user_with_memberships(self):
        invitation = self._create_invitation()
        self.client.logout()

        response = self.client.post(
            reverse("invitation_accept", args=[invitation.token]),
            data={
                "username": "newbie",
                "email": "",
                "password1": "strong-test-pass-123",
                "password2": "strong-test-pass-123",
            },
        )

        self.assertEqual(response.status_code, 302)
        user = get_user_model().objects.get(username="newbie")
        membership = AccountMembership.objects.get(user=user, account=self.account)
        self.assertEqual(membership.role, AccountMembership.Role.OPERATOR)
        invitation.refresh_from_db()
        self.assertEqual(invitation.accepted_by, user)

    def test_used_invitation_is_rejected(self):
        invitation = self._create_invitation()
        self.client.logout()
        self.client.post(
            reverse("invitation_accept", args=[invitation.token]),
            data={
                "username": "first",
                "password1": "strong-test-pass-123",
                "password2": "strong-test-pass-123",
            },
        )

        response = self.client.get(reverse("invitation_accept", args=[invitation.token]))

        self.assertEqual(response.status_code, 410)

    def test_unknown_token_rejected(self):
        self.client.logout()
        response = self.client.get(reverse("invitation_accept", args=["nope"]))
        self.assertEqual(response.status_code, 410)
