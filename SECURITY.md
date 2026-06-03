# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ |

## Reporting a Vulnerability

Deep-Scout takes security seriously. If you discover a security vulnerability, please **do not** open a public issue.

### Disclosure Process

1. **Report via email**: Send details to `security@deep-scout.io` (PGP key available on request)
2. **Include**: Description of the vulnerability, steps to reproduce, affected versions, and any potential impact
3. **Response time**: We acknowledge receipt within 48 hours and provide a timeline for the fix
4. **Disclosure**: We follow a 90-day disclosure policy — we release a fix before public disclosure

### What to Report

- Bypasses of detection engines (secrets that should be caught but aren't)
- False negative suppression (attacker config to hide secrets)
- Authentication or token leakage
- XSS or injection vulnerabilities in reports
- Any other security-relevant issue

### Scope

- The `deep-scout-github` PyPI package
- The `deep-scout` CLI tool
- HTML/JSON report output

### Out of Scope

- Third-party dependencies (report them to the respective maintainers)
- GitHub API rate limiting (by design)
- Secrets found in demo repositories

We appreciate responsible disclosure and will acknowledge your contribution in our release notes.
