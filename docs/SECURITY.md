# Security

InfraLens handles cloud credentials, so the default posture is conservative.

## Defaults

- Secrets are encrypted at rest with a Fernet key derived from `DJANGO_SECRET_KEY`. This covers cloud credentials (AWS keys, GCP service account JSON), AI provider API keys, and webhook URLs.
- Plaintext secrets are never returned to the UI. Edit forms accept new values but leave the stored secret untouched when their fields are blank.
- Scanners request read-only data.
- Findings store summaries and samples, not full raw logs.
- Remediation is never executed automatically.

## Production guidance

- Use short-lived AWS STS credentials or OIDC-based role assumption when possible.
- Rotate `DJANGO_SECRET_KEY` only with a planned credential re-encryption process.
- Restrict access to the Django admin.
- Run behind TLS.
- Keep the database private.

## Reporting issues

Do not open public issues for credential exposure or exploitable vulnerabilities. Use a private disclosure channel in your fork or organization until a project security contact is published.

