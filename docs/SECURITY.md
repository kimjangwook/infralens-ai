# Security

InfraLens handles cloud credentials, so the default posture is conservative.

## Defaults

- Secrets are encrypted at rest with a Fernet key derived from `DJANGO_SECRET_KEY`. This covers cloud credentials (AWS keys, GCP service account JSON), AI provider API keys, and webhook URLs.
- Plaintext secrets are never returned to the UI. Edit forms accept new values but leave the stored secret untouched when their fields are blank.
- Scanners request read-only data.
- Findings store summaries and samples, not full raw logs.
- Remediation is never executed automatically. AI remediation proposals are Markdown for human review.
- The inbound scan trigger webhook is authenticated by a per-account random token compared in constant time. The token only allows triggering a scan; it cannot read findings or credentials. Rotate it from the account page if it leaks, and serve it over TLS only.

## Production guidance

- Use short-lived AWS STS credentials or OIDC-based role assumption when possible.
- Rotate `DJANGO_SECRET_KEY` only with a planned credential re-encryption process.
- Restrict access to the Django admin.
- Run behind TLS.
- Keep the database private.

## Reporting issues

Do not open public issues for credential exposure or exploitable vulnerabilities. Use a private disclosure channel in your fork or organization until a project security contact is published.

