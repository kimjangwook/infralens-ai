# Roadmap

## Product thesis

InfraLens is the **briefing and insight layer** above raw cloud signals: it
turns read-only scan evidence into an infrastructure map, prioritized findings,
and AI-drafted proposals. The roadmap below is ordered to maximize two things:

1. **Evaluation value** — flagship features that demonstrate end-to-end product
   craft (graph engine, automation pipeline, multi-provider AI) and make the
   project a strong portfolio and hiring signal on its own.
2. **Revenue readiness** — an open-core path: the self-hosted core stays free
   and auditable, while hosted convenience and team features become paid tiers.

### Monetization model (open-core)

| Tier | Distribution | Price target | What it adds |
| --- | --- | --- | --- |
| Free | Self-hosted (this repo) | $0 | Full scanner, topology map, briefings, 1–2 accounts |
| Pro | Hosted or license key | ~$29/mo | Unlimited accounts, scheduling SLAs, AI proposal history, Slack/Notion export |
| Team | Hosted | ~$99/mo | Team RBAC, audit log export, custom rules, priority support |

The free tier is the marketing engine; every paid feature must be an
*operations convenience*, never a security downgrade of the free core.

## v0.1 — Scheduled job & cost briefing (shipped)

- AWS/GCP read-only cloud account setup
- Synchronous scan run from the dashboard
- Schedule map, log and cost findings
- Daily evidence-backed briefing (EN/JA/KO)
- Multi-provider AI (OpenAI, Anthropic, Google) with fallback
- First-run owner setup, per-account RBAC
- User-owned webhook endpoints and subscriptions

## v0.2 — Infrastructure graph & automation (shipped)

The "complete loop" release: see the whole infrastructure, keep it scanned
automatically, and get a fix proposal with one button.

- **Topology map**: schedules → targets → resources rendered as a Mermaid
  graph, globally and per account, built from scan evidence
- **Topology insights**: orphan schedule targets, untriggered workloads,
  fan-in hotspots, paused schedules — persisted as findings on every scan
- **In-app scan scheduling**: per-account interval schedules executed by the
  `run_scheduler` worker (docker-compose service / cron / systemd)
- **Inbound webhook trigger**: tokenized `POST /api/hooks/scan/...` endpoint so
  CI/CD or external cron can trigger scan → briefing → notifications
- **One-button remediation proposals**: AI-drafted root cause hypothesis, fix
  steps, commands/IaC snippet, rollback plan, and risk — with a deterministic
  fallback when AI is unavailable

## v0.3 — Coverage depth & exports

Make the map and briefings cover the signals teams actually pay attention to.

- AWS S3 / GCP GCS public exposure checks
- BigQuery Billing Export scanner (GCP cost parity with AWS)
- Scan-to-scan change diff ("what changed since yesterday") in briefings
- Slack-formatted webhook export and Notion export
- Resource detail pages with finding and proposal history

## v0.4 — Scale & integration

Remove the synchronous ceiling and meet teams where they work.

- Background worker queue for long scans (no request-bound scanning)
- Multi-account combined daily report
- GitHub issue creation from findings and proposals
- IAM / network edge expansion of the topology graph
- Prometheus-style metrics endpoint for the scheduler

## v0.5 — Monetization infrastructure

Everything needed to charge money without rewriting the product.

- Hosted beta (multi-tenant deployment profile, Postgres support)
- Stripe billing with tier enforcement (accounts, history retention, seats)
- Usage metering (scans, AI tokens) and plan limits
- Team workspaces and invitations

## v1.0 — Commercial launch

- Hosted GA with SLA
- Custom rule engine (user-defined detectors and severities)
- Audit log export, SOC 2 preparation checklist
- Kubernetes and Azure scanners
- Public template gallery of webhook/automation recipes
