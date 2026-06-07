# API and scanner notes

InfraLens currently runs scans from the web UI or management command layer. The core flow is:

```text
CloudAccount credentials
  -> ScanRun
  -> Resource / Schedule snapshots
  -> Finding
  -> DailyBriefing
```

Briefing generation uses the global settings language and model. When `OPENAI_API_KEY` is available, InfraLens calls the OpenAI Responses API to generate evidence-backed insights. If the API call fails, InfraLens stores a deterministic fallback briefing in the same configured language.

## AWS scanner

The AWS scanner uses `boto3` and static credentials or session credentials stored encrypted in the database.

Current coverage:

- EventBridge scheduled rules and targets
- Lambda inventory
- CloudWatch Logs error/timeout sampling for Lambda log groups
- Cost Explorer daily service costs

## GCP scanner

The GCP scanner uses a service account JSON and REST APIs through `google-auth`.

Current coverage:

- Cloud Scheduler jobs
- Cloud Run services and jobs
- Cloud Logging error sampling

Billing export integration is planned as a BigQuery-based scanner.

## AI model

Default model:

```text
gpt-5.4-mini-2026-03-17
```

The model can be changed from the global Settings screen.
