# SOC 2 Preparation Checklist

A practical starting point for operating InfraLens (self-hosted or hosted)
toward a SOC 2 Type I/II engagement. This is preparation guidance, not a
substitute for an auditor.

## Security (Common Criteria)

- [ ] Unique `DJANGO_SECRET_KEY` per environment, stored in a secret manager, never in git.
- [ ] TLS termination in front of the app; HSTS enabled (default when `DEBUG=false`).
- [ ] Owner/admin accounts use strong passwords; remove unused accounts quarterly.
- [ ] Per-account RBAC reviewed quarterly (Users -> Access). Use viewer-by-default.
- [ ] Cloud credentials are read-only (see `examples/aws-readonly-policy.json`, `examples/gcp-minimal-roles.md`).
- [ ] Webhook trigger tokens rotated on personnel change (account page -> Rotate token).
- [ ] `/metrics` token and Stripe webhook secret stored as secrets, rotated yearly.

## Availability

- [ ] Database volume backed up daily; restore tested at least twice a year.
- [ ] Scheduler and worker processes supervised (compose restart policy or systemd).
- [ ] `/healthz` wired into uptime monitoring; `/metrics` scraped for queue depth and scan failures.

## Confidentiality

- [ ] All stored secrets (cloud credentials, AI keys, webhook URLs, GitHub token) remain encrypted at rest — never bypass the app layer to write them.
- [ ] Raw log retention stays disabled (`INFRALENS_STORE_RAW_LOGS=false`) unless a documented need exists.
- [ ] AI providers reviewed for data processing terms; disable AI (`INFRALENS_AI_ENABLED=false`) if briefing data must not leave the boundary.

## Processing Integrity

- [ ] CI green on every deploy (`manage.py test`, migration check).
- [ ] Scan failures alert via webhook subscriptions at `warning` severity or above.
- [ ] Custom rules reviewed when infrastructure conventions change.

## Audit & Change Management

- [ ] Audit log exported (Audit -> Export CSV) monthly and archived immutably.
- [ ] Login, account, scan, settings, and export events are recorded automatically; verify after upgrades.
- [ ] All production changes flow through pull requests on the deployment repo.

## Privacy (if applicable)

- [ ] Webhook payloads contain finding summaries only; confirm downstream systems (Slack, Notion, GitHub) match your data classification.
- [ ] Invitation links are time-boxed (7 days) and single-use; do not share through public channels.
