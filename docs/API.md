# API and scanner notes

InfraLens currently runs scans from the web UI or management command layer. The core flow is:

```text
CloudAccount credentials
  -> ScanRun
  -> Resource / Schedule snapshots
  -> Finding
  -> DailyBriefing
```

Briefing generation uses the global settings language and the default AI provider configured under Settings -> AI providers. Depending on the provider it calls the OpenAI Responses API, the Anthropic Messages API, or the Google Gemini generateContent API, using the encrypted API key stored for that provider. If no active provider is set or the API call fails, InfraLens stores a deterministic fallback briefing in the same configured language.

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

Providers and models are configured under Settings -> AI providers. Each provider
stores its own model id and encrypted API key, and one is marked as the default
used for briefings. The form suggests current models per provider, for example:

```text
OpenAI     gpt-5.5
Anthropic  claude-opus-4-8
Google     gemini-3.5-flash
```

Any model id can be entered; the suggestions are a convenience, not a fixed list.
