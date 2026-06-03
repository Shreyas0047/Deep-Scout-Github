# Deep-Scout Demo

This directory contains files with **intentionally placed synthetic secrets** for testing Deep-Scout.

All credentials here are fake — they match the pattern format but are not valid keys for any service.

## Quick Test

```bash
# Scan this demo directory (no GitHub token needed for local scans)
deep-scout scan --files-only --no-github --path ./demo
```

## What's Included

| File | Secrets |
|------|---------|
| `config/aws-keys.yml` | AWS Access Key, AWS Secret Key |
| `.env` | PostgreSQL URL, Redis URL, JWT Token, custom secret key |
| `keys/ssh-private.key` | RSA Private Key (fake) |
| `config/slack.yml` | Slack Webhook URL, Slack Bot Token |
| `config/stripe.yml` | Stripe Live Key, Stripe Test Key, Stripe Webhook Secret |

> **Note:** These are detection test fixtures, not real credentials. The AWS keys shown are the official AWS documentation examples.
