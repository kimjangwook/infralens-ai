# API and scanner notes

InfraLens runs scans from the web UI, the management command layer, the in-app
scheduler, or the inbound trigger webhook. Every path runs the same pipeline:

```text
CloudAccount credentials
  -> ScanRun
  -> Resource / Schedule snapshots
  -> Finding (schedule / logs / cost / topology)
  -> topology analysis (orphan targets, untriggered workloads, hotspots)
  -> DailyBriefing
  -> webhook notifications
```

## Inbound scan trigger webhook

```text
POST /api/hooks/scan/<account-id>/<token>/
```

- No session or CSRF token required; the per-account secret token in the URL
  authenticates the caller (compared in constant time).
- On success returns `200` with `{"scan_run": ..., "status": "success", "summary": {...}}`.
- A failed scan returns `502` with the error message; a wrong token returns
  `403`; an unknown account returns `404`. `GET` is rejected with `405`.
- The URL is shown to account admins on the account page, where the token can
  also be rotated.

## Scheduler

`ScanSchedule` rows hold one interval per account (hourly to weekly). The
`run_scheduler` management command executes due schedules through the same
pipeline:

```bash
python manage.py run_scheduler                 # one pass, for cron/systemd timers
python manage.py run_scheduler --loop          # poll every 60s (compose service)
python manage.py run_scheduler --loop --poll-seconds 30
```

## Remediation proposals

`POST /findings/<finding-id>/propose/` (session auth, operator role) generates
a `RemediationProposal` for the finding using the default AI provider. The
prompt contains the finding evidence plus its topology neighborhood. When AI is
disabled or fails, a deterministic template proposal is stored instead with
status `fallback`.

Briefing generation uses the global settings language and the default AI provider configured under Settings -> AI providers. Depending on the provider it calls the OpenAI Responses API, the Anthropic Messages API, or the Google Gemini generateContent API, using the encrypted API key stored for that provider. If no active provider is set or the API call fails, InfraLens stores a deterministic fallback briefing in the same configured language.

## AWS scanner

The AWS scanner uses `boto3` and static credentials or session credentials stored encrypted in the database.

Current coverage:

- EventBridge scheduled rules and targets
- Lambda inventory
- CloudWatch Logs error/timeout sampling for Lambda log groups
- Cost Explorer daily service costs
- S3 bucket inventory with public-policy and public-access-block exposure checks

## GCP scanner

The GCP scanner uses a service account JSON and REST APIs through `google-auth`.

Current coverage:

- Cloud Scheduler jobs
- Cloud Run services and jobs
- Cloud Logging error sampling
- GCS bucket inventory with allUsers/allAuthenticatedUsers and public-access-prevention checks
- BigQuery Billing Export cost anomalies, when a `project.dataset.table` id is configured on the account

## Kubernetes scanner

Uses an API server URL plus a read-only ServiceAccount bearer token (bind the
`view` ClusterRole). Coverage: CronJobs (as schedules), Deployments with
unavailable replicas, and warning events.

## Azure scanner

Uses a service principal (tenant, client id/secret, subscription) with the
Reader role. Coverage: Function/Web Apps (stopped apps flagged), Logic App
workflows (as schedules), and error-level Activity Log sampling.

## Change diff

Every scan compares its inventory against the previous one. Stale rows are
deleted so the topology stays current, and a `change` finding lists added and
removed resources and schedules when something differs.

## Custom rules

`CustomRule` rows (global or per account) are evaluated after every scan
against resources or schedules. A rule matches one field (`name`, `region`,
`state`, `metadata.timeout`, ...) with an operator (equals, contains, gt, lt,
regex, ...) and produces findings in the `custom` category.

## AI model

Providers and models are configured under Settings -> AI providers. Each provider
stores its own model id and encrypted API key, and one is marked as the default
used for briefings. The form suggests current models per provider, for example:

```text
OpenAI     gpt-5.5
Anthropic  claude-opus-4-8
Google     gemini-3.1-pro-preview
```

Any model id can be entered; the suggestions are a convenience, not a fixed list.
