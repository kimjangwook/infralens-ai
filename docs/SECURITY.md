# Security

InfraLens handles cloud credentials, so the default posture is conservative.

## Defaults

- Credentials are encrypted at rest with a key derived from `DJANGO_SECRET_KEY`.
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

