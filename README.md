<p align="center">
  <img src="logo.svg" alt="Deep-Scout Logo" width="500">
</p>

<p align="center">
  <strong>Deep reconnaissance on GitHub organizations to uncover accidentally committed secrets.</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#demo">Demo</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#detection-capabilities">Detection</a> •
  <a href="#output-formats">Reports</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#ci-cd-integration">CI/CD</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
  <img src="https://img.shields.io/badge/status-beta-yellow" alt="Beta">
  <img src="https://img.shields.io/pypi/v/deep-scout-github" alt="PyPI">
  <img src="https://img.shields.io/github/actions/workflow/status/yourusername/deep-scout-github/scan.yml?branch=main" alt="CI">
  <img src="https://img.shields.io/badge/code%20style-ruff-261230" alt="Ruff">
</p>

---

Deep-Scout is a CLI tool that scans entire GitHub organizations for accidentally committed secrets — AWS keys, API tokens, database passwords, SSH private keys, and more. It uses **regex pattern matching** for known secret formats and **Shannon entropy analysis** to catch custom-formatted secrets, then provides actionable remediation steps for every finding.

Built for security engineers, DevOps teams, and bug bounty hunters who need to protect their organizations from credential exposure.

---

## Features

- **Organization-wide scanning** — Scan all repos in a GitHub org with a single command
- **Dual detection engines** — Regex (28 built-in patterns) + Shannon entropy analysis
- **Intelligent whitelist** — Built-in false positive filtering (UUIDs, commit hashes, test keys, etc.) + user-extensible
- **Live progress UI** — Real-time terminal dashboard with per-repo progress bars and findings count
- **Remediation-first** — Every finding comes with risk assessment, step-by-step fix instructions, revoke URLs, and git cleanup commands
- **Multiple output formats** — Interactive HTML dashboard, structured JSON, Slack webhook notifications
- **CI/CD ready** — Exit codes, GitHub Actions integration, SARIF-compatible JSON
- **Pre-commit hook** — Prevent secrets from being committed in the first place
- **Context analysis** — Boosts confidence when secrets appear near variable names like `SECRET_KEY`, `password`, `token`
- **AWS key validation** — (optional) Verify found AWS keys against IAM API
- **Performance optimized** — Shallow cloning, parallel repo scanning, file filtering, smart caching

## Demo

Try Deep-Scout immediately on a local directory of synthetic secrets — no GitHub token required:

```bash
# Clone the repo
git clone https://github.com/yourusername/deep-scout-github
cd deep-scout-github

# Install
pip install .

# Scan the demo directory
deep-scout scan --org demo
```

This scans the `demo/` folder containing intentionally placed fake credentials (AWS keys, Slack tokens, database URLs, SSH keys). You'll see the full pipeline: detection, whitelist filtering, remediation output, and an HTML report.

> **Warning:** The demo secrets are synthetic and harmless. Do not use them anywhere — they are detection test fixtures only.

## Quick Start

```bash
# Install
pip install deep-scout-github

# Set your GitHub token
export GITHUB_TOKEN="ghp_yourTokenHere"

# Scan an organization
deep-scout scan --org your-org

# View the interactive HTML report
open deep-scout-reports/deep-scout-report-your-org.html
```

### Prerequisites

- **Python 3.10+**
- **Git** (for cloning repositories)
- **GitHub personal access token** with `repo` scope (for private repos) or `public_repo` scope (for public repos)

### Installation Options

```bash
# PyPI (recommended)
pip install deep-scout-github

# From source
git clone https://github.com/yourusername/deep-scout-github
cd deep-scout-github
pip install -e .

# Docker
docker pull deepscout/deep-scout-github:latest
docker run -e GITHUB_TOKEN=$GITHUB_TOKEN deepscout/deep-scout-github scan --org my-company
```

## Usage

### Scan an organization

```bash
deep-scout scan --org netflix
```

### Scan a single repository

```bash
deep-scout scan --org netflix --repo security-tools
```

### Scan with options

```bash
deep-scout scan --org netflix \
  --depth 50 \
  --entropy-threshold 4.2 \
  --format json \
  --output ./reports \
  --fail-on-secret \
  --no-entropy \
  --strict
```

### Calculate entropy of a string

```bash
deep-scout entropy "AKIAIOSFODNN7EXAMPLE"
# Output: Entropy: 3.68 bits/byte — MEDIUM
```

### Manage whitelist

```bash
# List all built-in whitelist rules
deep-scout whitelist list

# Add a custom whitelist pattern
deep-scout whitelist add --pattern "example-key-[0-9]+" --reason "Our company example keys"

# Remove a custom pattern
deep-scout whitelist remove --pattern "example-key-[0-9]+"
```

### Install pre-commit hook

```bash
deep-scout install-hook
```

### Security: --strict mode

Project-level `.deep-scout.yaml` files in the current directory are loaded automatically. An attacker who compromises a repository could add a malicious config to disable detection or whitelist their secrets.

Use `--strict` to ignore project-level config and load only `~/.deep-scout/config.yaml`:

```bash
deep-scout scan --org netflix --strict
```

## Exit Codes

| Code | Meaning | CI Action |
|------|---------|-----------|
| `0` | No secrets found | Pipeline continues |
| `1` | Secrets found | Pipeline fails, block merge |
| `2` | Authentication error | Check `GITHUB_TOKEN` |
| `4` | Invalid arguments | Check command syntax |
| `5` | Network error | Check connectivity |

## Detection Capabilities

### Method 1: Regex Pattern Matching (28 patterns)

| Secret Type | Severity | Example |
|-------------|----------|---------|
| AWS Access Key | Critical | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | Critical | Base64-encoded 40-char secret |
| AWS Session Token | High | Temporary credential string |
| GitHub Token (Classic) | Critical | `ghp_...` |
| GitHub Token (Fine-grained) | Critical | `github_pat_...` |
| GitHub App Token | Critical | `ghs_...` |
| Slack Webhook | High | `https://hooks.slack.com/services/...` |
| Slack Token | High | `xoxb-...` |
| Stripe Live Key | Critical | `sk_live_...` |
| Stripe Test Key | Low | `sk_test_...` |
| Stripe Webhook Secret | High | `whsec_...` |
| Google API Key | High | `AIza...` |
| Google OAuth Client ID | High | `...apps.googleusercontent.com` |
| SendGrid API Key | High | `SG....` |
| Twilio API Key | High | `SK...` |
| Twilio Account SID | High | `AC...` |
| SSH Private Key | Critical | `-----BEGIN RSA PRIVATE KEY-----` |
| PGP Private Key | Critical | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| PostgreSQL URL | High | `postgresql://user:pass@host/db` |
| MySQL URL | High | `mysql://user:pass@host/db` |
| MongoDB URL | High | `mongodb://user:pass@host/db` |
| Redis URL | High | `redis://user:pass@host:6379` |
| JWT Token | High | `eyJ...` |
| NPM Token | High | `npm_...` |
| PyPI Token | High | `pypi-...` |
| Bearer Token | High | `Bearer eyJ...` |
| Private Key in Variable | Critical | `PRIVATE_KEY = "..."` |

### Method 2: Shannon Entropy Analysis

Deep-Scout calculates Shannon entropy of every alphanumeric string (16+ characters) in each file. High-entropy strings (default threshold: 4.5 bits/byte) are flagged as potential secrets.

**Context analysis** boosts confidence when high-entropy strings appear near variable names like `SECRET_KEY`, `password`, `token`, `api_key`, `private_key`.

### Whitelist System

Built-in rules filter out common false positives:

```
UUID v4                         123e4567-e89b-...
Git commit hash (SHA-1)         a1b2c3d4e5f6...
Git commit hash (SHA-256)       5e884898da28...
AWS example key                 AKIAIOSFODNN7EXAMPLE
AWS example secret              wJalrXUtnFEMI/...
Environment variable ref        ${VAR} or $VAR
Stripe test key                 sk_test_...
Localhost URLs                  localhost
Docker container IDs            a1b2c3d4e5f6
Test data                       test[a-z0-9_]*
```

Users can extend the whitelist via `.deep-scout.yaml` or the `whitelist add` command.

## Remediation

Every finding includes structured remediation:

- **Risk assessment** — What an attacker can do with this secret
- **Immediate steps** — Ordered actions (revoke, rotate, audit, clean)
- **Revoke URLs** — One-click links to revoke at the provider's console
- **Git cleanup command** — Ready-to-run `bfg` command to scrub history
- **Prevention tips** — How to avoid recurrence

Example terminal output for critical findings:

```
🚨 AWS Access Key (CRITICAL)
   Repos: netflix/security-tools, netflix/conductor
   → Revoke: https://console.aws.amazon.com/iam/home#/security_credentials
   → 1. Immediately revoke the exposed key via AWS IAM console
```

In the HTML report, each finding expands to show the full remediation guide with clickable revoke buttons and copy-to-clipboard git cleanup commands.

## Output Formats

### HTML Dashboard

An interactive, standalone HTML file with:
- Summary cards with severity counts
- Severity filter tabs (All / Critical / High / Medium / Low)
- Search by repository or secret type
- Expandable finding rows with remediation guides, risk boxes, revoke buttons, and git cleanup commands
- Dark theme, responsive design

### JSON (Machine-readable)

Structured output for CI/CD pipelines, SIEM integration, and automation:

```bash
deep-scout scan --org netflix --format json
```

### Slack Notifications

Real-time alerts to your security channel with:
- Severity-colored headers
- Inline remediation steps
- Revoke action buttons

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
deep-scout scan --org netflix --format slack
```

## Configuration

Deep-Scout reads configuration from `~/.deep-scout/config.yaml` (user-global) and `./.deep-scout.yaml` (project-specific, takes precedence).

```yaml
# ~/.deep-scout/config.yaml
github:
  token: ${GITHUB_TOKEN}
  base_url: https://api.github.com

scanning:
  max_commit_depth: 100
  exclude_repos:
    - "archived-*"
    - "docs"
  exclude_paths:
    - "**/node_modules/**"
    - "**/vendor/**"

detection:
  enable_entropy: true
  entropy_threshold: 4.5
  custom_patterns:
    - name: "Internal API Key"
      pattern: "X-API-Key:\\s+([A-Za-z0-9]{32})"
      severity: high
  custom_whitelist:
    - pattern: "test[0-9]+"
      reason: "Test data"
      type: regex

reporting:
  default_format: html
  mask_secrets_in_report: true

performance:
  parallel_repos: 3
  cache_enabled: true
  cache_ttl_hours: 24
```

> **Security note:** Never commit `.deep-scout.yaml` to a repository. An attacker could use it to disable detection. Use `--strict` mode to ignore project-level config.

## CI/CD Integration

### GitHub Actions

```yaml
name: Deep-Scout Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 100

      - name: Run Deep-Scout
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          pip install deep-scout-github
          deep-scout scan --org ${{ github.repository_owner }} \
            --repo ${{ github.event.repository.name }} \
            --format json \
            --output deep-scout-report.json \
            --fail-on-secret
```

### Pre-commit Hook

```bash
deep-scout install-hook
```

The hook scans staged files before every commit and blocks the commit if secrets are detected.

## Architecture

```
GitHub Organization
        │
        ▼
[GitHub API Client] ──► List of Repositories
        │
        ▼
For each repository (parallel):
        │
        ├──► Shallow clone (git clone --depth N)
        │
        ▼
[File System Walker] ──► Filter by extension, skip binaries
        │
        ▼
For each file:
        │
        ├──► [Regex Detector] ──► 28 built-in patterns + custom
        │
        ├──► [Entropy Detector] ──► Shannon entropy + context analysis
        │
        ▼
[Whitelist Filter] ──► Remove false positives
        │
        ▼
[Deduplication] ──► Group identical secrets
        │
        ▼
[Report Generator] ──► HTML / JSON / Slack
```

## Performance

| Repository Size | Files | Scan Time | Memory |
|----------------|-------|-----------|--------|
| Small (100 files) | 100 | 2-5s | 50 MB |
| Medium (1,000 files) | 1,000 | 10-30s | 150 MB |
| Large (10,000 files) | 10,000 | 1-3 min | 500 MB |
| Organization (100 repos) | 100,000 | 15-30 min | 2-3 GB |

## Security & Privacy

- **No telemetry** — Deep-Scout phones home to no servers
- **Local processing** — All scanning happens on your machine
- **Temporary clones** — Repos cloned to temp dirs, deleted after scan
- **No secret storage** — Secrets never written to disk except in your report
- **Masked by default** — Reports show `AKIA************EXAMPLE`, not full secrets
- **`--strict` mode** — Ignores project-level config files to prevent tampering
- **XSS-safe reports** — All user-controlled values are escaped in HTML output
- **Minimal token scope** — Only `repo` or `public_repo` scope needed

## Development

```bash
git clone https://github.com/yourusername/deep-scout-github
cd deep-scout-github
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=deep_scout

# Lint
ruff check .

# Type check
mypy deep_scout/
```

## License

MIT
