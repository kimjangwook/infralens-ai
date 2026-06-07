# InfraLens AI

Self-hosted AI CloudOps analyst for AWS and GCP.

InfraLens connects to read-only AWS/GCP credentials, scans scheduled jobs, logs, and cost signals, then turns cloud noise into evidence-backed daily briefings. It is built for small teams that do not have a full-time SRE but still need a clear answer to: "What should we check today?"

InfraLens is not a Datadog, Wiz, CloudQuery, or Steampipe replacement. It is a briefing and analysis layer above cloud-native and open-source operational signals.

## What It Does

- Scans AWS EventBridge rules, Lambda functions, CloudWatch Logs, and Cost Explorer
- Scans GCP Cloud Scheduler, Cloud Run, and Cloud Logging
- Detects schedule, log, and cost findings with evidence
- Generates AI daily briefings in English, Japanese, or Korean
- Renders briefings as Markdown, not raw code blocks
- Supports first-run owner setup, login, users, and per-cloud-account RBAC
- Sends scan findings to user-owned webhook subscriptions
- Stores cloud credentials and webhook URLs encrypted at rest

## Current MVP Scope

The first version focuses on **Scheduled Cloud Job & Cost Anomaly Briefing**.

Included:

- AWS EventBridge -> target map
- AWS Lambda inventory
- AWS CloudWatch error/timeout sampling
- AWS Cost Explorer spike hints
- GCP Cloud Scheduler jobs
- GCP Cloud Run services/jobs
- GCP Cloud Logging error sampling
- Daily briefing generation
- Generic webhook notifications

Not included yet:

- Kubernetes
- Azure
- Automatic remediation
- Full raw log retention
- Advanced ML anomaly detection
- Full network/IAM graphing

## Trust Model

- Read-only first
- Self-hosted by default
- Credentials encrypted at rest
- Webhook URLs encrypted at rest
- No raw log retention by default
- No automatic remediation
- Suggested actions are proposals only

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000
```

On first run, InfraLens redirects to `/setup/`. Create the first owner account there. The first owner can manage users, global settings, cloud account access, and webhook subscriptions.

Django Admin remains available at `/admin/` for emergency database management, but it is not part of the product navigation.

## Environment Variables

Copy `.env.example` to `.env`.

Required for real use:

- `DJANGO_SECRET_KEY`: encryption and Django signing key. Change this before production use.
- `OPENAI_API_KEY`: used for AI briefing generation.

Common optional values:

- `DJANGO_DEBUG`: `true` for local development, `false` for production.
- `DJANGO_ALLOWED_HOSTS`: comma-separated hostnames.
- `INFRALENS_DB_PATH`: SQLite database path.
- `OPENAI_MODEL`: default AI model value before it is changed in Settings.
- `INFRALENS_STORE_RAW_LOGS`: reserved for future raw-log retention; keep `false`.

## AI Briefings

InfraLens uses the OpenAI Responses API when `OPENAI_API_KEY` is configured.

Default model:

```text
gpt-5.4-mini-2026-03-17
```

The Settings screen lets an owner choose from multiple briefing models and choose the report language:

- English
- Japanese
- Korean

If the OpenAI API is unavailable, InfraLens stores a deterministic fallback briefing in the same configured language.

## AWS Permissions

For the current scanner, attach a read-only policy similar to:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "events:ListRules",
        "events:ListTargetsByRule",
        "lambda:ListFunctions",
        "logs:FilterLogEvents",
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
}
```

See [examples/aws-readonly-policy.json](examples/aws-readonly-policy.json).

## GCP Permissions

For the current scanner, use a service account with read-only access to:

- Cloud Scheduler jobs
- Cloud Run viewer permissions
- Cloud Logging viewer permissions

GCP service-level cost anomaly support will use BigQuery Billing Export in a later version.

See [examples/gcp-minimal-roles.md](examples/gcp-minimal-roles.md).

## User Access

Cloud account access is controlled per user.

| Role | Access |
| --- | --- |
| `viewer` | View findings, resources, schedules, and reports |
| `operator` | Viewer plus scan and briefing generation |
| `admin` | Operator plus account-level management |
| `owner` | Full account ownership |

Global admins can create cloud accounts, manage users, and edit global settings.

## Webhook Notifications

Each user can create webhook endpoints and subscribe them to cloud accounts they can access.

After a scan finishes:

```text
ScanRun
  -> open findings from that scan
  -> matching subscriptions
  -> membership check for endpoint owner
  -> webhook POST
  -> NotificationDelivery result
```

Webhook payloads include finding summaries and evidence. They never include cloud credentials or raw logs.

## Optional Demo Data

After first-run setup and login:

```bash
python manage.py seed_demo
```

This creates a demo AWS account, sample schedule, sample findings, and a briefing.

## Docker

```bash
docker compose up --build
```

For production, set a strong `DJANGO_SECRET_KEY`, set `DJANGO_DEBUG=false`, and put the app behind TLS.

## Project Structure

```text
infralens/
  settings.py
ops/
  models.py          # accounts, memberships, scans, findings, webhooks
  scanners/          # AWS/GCP read-only scanners
  templates/         # Django + HTMX UI
  static/            # dashboard JS/CSS
docs/
examples/
scripts/
```

## Development

```bash
python manage.py check
python manage.py test
python manage.py makemigrations --check --dry-run
```

## Positioning

CloudQuery collects cloud data. InfraLens turns operational signals into daily actions.

Datadog monitors systems. InfraLens briefs small teams on what to check today.

## License

MIT
