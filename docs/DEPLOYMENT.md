# Deployment

InfraLens is a single Django app with a SQLite database, served by gunicorn with
WhiteNoise for static files. It is designed to be self-hosted on one small host.

## Pre-flight checklist

- [ ] Set a unique `DJANGO_SECRET_KEY`. With `DJANGO_DEBUG=false` the app refuses to start on the default key.
- [ ] Set `DJANGO_DEBUG=false`.
- [ ] Set `DJANGO_ALLOWED_HOSTS` to your real hostname(s), comma-separated.
- [ ] Terminate TLS in front of the app (reverse proxy or load balancer).
- [ ] Set `DJANGO_CSRF_TRUSTED_ORIGINS` to your `https://` origin(s) if forms are served over HTTPS behind a proxy.
- [ ] Mount a persistent volume for the SQLite database (`INFRALENS_DB_PATH`).
- [ ] Back up the database volume on a schedule. It holds encrypted credentials and findings.
- [ ] Keep `DJANGO_SECRET_KEY` backed up. It is the encryption key; losing it makes stored credentials and API keys unrecoverable.

## What `DEBUG=false` turns on

When `DJANGO_DEBUG=false`, settings enable:

- `SECURE_SSL_REDIRECT` (override with `DJANGO_SECURE_SSL_REDIRECT=false` if TLS is terminated elsewhere and you do not want app-level redirects)
- `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE`
- HSTS (`DJANGO_SECURE_HSTS_SECONDS`, default 30 days)
- `SECURE_CONTENT_TYPE_NOSNIFF` and `X_FRAME_OPTIONS=DENY`
- `SECURE_PROXY_SSL_HEADER` so the app trusts `X-Forwarded-Proto` from your proxy
- Compressed, hashed static files via WhiteNoise

## Reverse proxy

Forward `X-Forwarded-Proto` so Django knows the original request was HTTPS:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## Environment variables

| Variable | Purpose |
| --- | --- |
| `DJANGO_SECRET_KEY` | Signing and encryption key. Required, unique, secret. |
| `DJANGO_DEBUG` | `false` in production. |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated hostnames. |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Comma-separated `https://` origins, if behind a proxy. |
| `DJANGO_SECURE_SSL_REDIRECT` | `false` to disable app-level HTTPS redirect. |
| `DJANGO_SECURE_HSTS_SECONDS` | HSTS max-age. |
| `INFRALENS_DB_PATH` | SQLite path; point at a mounted volume. |
| `INFRALENS_AI_ENABLED` | `false` to disable AI calls and always use the fallback briefing. |

AI provider keys are configured in the app (Settings -> AI providers), not via
environment variables, and are stored encrypted.

## Scheduled scans

The web UI runs scans synchronously. For unattended daily briefings, run the
management command from cron on the host or container:

```bash
python manage.py scan_account <account-id>
```

## Rotating the secret key

`DJANGO_SECRET_KEY` is also the encryption key. Rotating it makes existing
encrypted credentials, AI keys, and webhook URLs undecryptable. Plan a rotation
by re-entering each secret after the change, or build an explicit re-encryption
step before rotating.
