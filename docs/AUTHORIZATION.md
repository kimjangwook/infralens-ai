# Authorization model

InfraLens uses product-level login, not Django Admin, for normal operation.

## First-run setup

When no users exist, `/setup/` is public. The first account created there becomes the owner:

- `is_staff = true`
- `is_superuser = true`

After that, `/setup/` closes automatically.

## Global admins

Global admins can:

- Create, edit, and delete cloud accounts
- Manage AI providers (provider, model, and encrypted API key)
- Manage users
- Edit global settings
- Access all cloud accounts

Editing a cloud account requires the account `admin` role or a global admin. Deleting requires the account `owner` role or a global admin. Editing leaves the stored credentials in place unless new secret values are entered. AI provider management requires a global admin.

## Cloud account roles

Access is assigned through `AccountMembership`.

| Role | Permission |
| --- | --- |
| viewer | View findings, resources, schedules, and reports |
| operator | Run scans and generate briefings |
| admin | Manage account-level settings and credentials, edit the account |
| owner | Full account ownership, delete the account |

## Webhooks

Users create their own `WebhookEndpoint` records. A `NotificationSubscription` connects that endpoint to a cloud account and minimum severity.

On scan completion:

```text
ScanRun
  -> open findings from that scan
  -> subscriptions for the account
  -> membership check for endpoint owner
  -> webhook POST
  -> NotificationDelivery result
```

Webhook URLs are encrypted at rest and should be treated as secrets.
