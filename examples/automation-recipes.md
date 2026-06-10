# Automation Recipe Gallery

Copy-paste recipes for wiring InfraLens into the tools around it. Replace
`HOST`, `ACCOUNT_ID`, and `TOKEN` with the values from the account page.

## 1. Scan after every deploy (GitHub Actions)

```yaml
- name: Trigger InfraLens scan
  run: |
    curl -fsS -X POST \
      "https://HOST/api/hooks/scan/ACCOUNT_ID/TOKEN/"
```

## 2. Nightly scan from external cron

```cron
15 0 * * * curl -fsS -X POST https://HOST/api/hooks/scan/ACCOUNT_ID/TOKEN/ >/dev/null
```

(Or skip the webhook entirely and enable the in-app schedule; the
`scheduler` service runs it.)

## 3. Critical findings to Slack

1. Create a Slack incoming webhook in your workspace.
2. InfraLens -> Webhooks -> Add endpoint, provider **Slack incoming webhook**, paste the URL.
3. Add a subscription for the account with min severity **Critical** (or Warning).

Scan findings arrive as Slack messages with one section per finding.

## 4. Daily combined report to Notion

1. Create a Notion integration, copy the `secret_...` token, and share a parent page with it.
2. InfraLens -> Webhooks -> Add endpoint, provider **Notion page export**, token + parent page id, check **receive daily report**.
3. Settings -> enable the combined daily report and pick the UTC hour.

Every day a new Notion page appears under the parent with the briefing.

## 5. Findings into GitHub issues

1. Create a fine-grained GitHub token with `issues:write` on the ops repo.
2. Settings -> set GitHub repository (`owner/repo`) and the token.
3. On any finding page, press **Create GitHub issue**.

## 6. Grafana panel from /metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: infralens
    metrics_path: /metrics
    params:
      token: ["YOUR_METRICS_TOKEN"]
    static_configs:
      - targets: ["HOST"]
```

Useful series: `infralens_open_findings{severity="critical"}`,
`infralens_scan_runs_total{status="failed"}`, `infralens_jobs{status="queued"}`.

## 7. Async scans under heavy load

```bash
INFRALENS_ASYNC_SCANS=true docker compose up -d
```

The scan button and trigger webhook now enqueue jobs; the `worker` service
processes them. The webhook returns `202` with a job id.

## 8. Custom rule examples

| Goal | Target | Field | Operator | Value |
| --- | --- | --- | --- | --- |
| Flag Lambdas with timeout > 60s | resource | `metadata.timeout` | gt | `60` |
| Flag schedules without prod prefix | schedule | `name` | not_contains | `prod-` |
| Flag resources in unexpected region | resource | `region` | not_equals | `ap-northeast-1` |
| Flag suspended CronJobs | schedule | `state` | equals | `SUSPENDED` |
