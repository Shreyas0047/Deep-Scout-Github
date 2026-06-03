from __future__ import annotations

import re
from typing import Any, NamedTuple


class RegexPattern(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    severity: str  # "critical", "high", "medium", "low"
    description: str = ""


BUILTIN_PATTERNS: list[RegexPattern] = [
    RegexPattern("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "AWS access key ID"),
    RegexPattern("AWS Secret Key", re.compile(r"aws(.{0,20})?[\"'][A-Za-z0-9/+=]{40}[\"']", re.IGNORECASE), "critical", "AWS secret access key"),
    RegexPattern("AWS Session Token", re.compile(r"FwoGZXIvYXdzE[=a-zA-Z0-9/+]+"), "high", "AWS session token"),
    RegexPattern("GitHub Token (Classic)", re.compile(r"ghp_[A-Za-z0-9]{36}"), "critical", "GitHub personal access token (classic)"),
    RegexPattern("GitHub Token (Fine-grained)", re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"), "critical", "GitHub fine-grained token"),
    RegexPattern("GitHub App Token", re.compile(r"ghs_[A-Za-z0-9]{36}"), "critical", "GitHub app token"),
    RegexPattern("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "high", "Slack incoming webhook URL"),
    RegexPattern("Slack Token", re.compile(r"xox[baprs]-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+"), "high", "Slack API token"),
    RegexPattern("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "critical", "Stripe live secret key"),
    RegexPattern("Stripe Test Key", re.compile(r"sk_test_[0-9a-zA-Z]{24}"), "low", "Stripe test secret key"),
    RegexPattern("Stripe Webhook Secret", re.compile(r"whsec_[A-Za-z0-9]{24}"), "high", "Stripe webhook signing secret"),
    RegexPattern("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high", "Google API key"),
    RegexPattern("Google OAuth Client ID", re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "high", "Google OAuth client ID"),
    RegexPattern("SendGrid API Key", re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"), "high", "SendGrid API key"),
    RegexPattern("Twilio API Key", re.compile(r"SK[0-9a-f]{32}"), "high", "Twilio API key"),
    RegexPattern("Twilio Account SID", re.compile(r"AC[0-9a-f]{32}"), "high", "Twilio account SID"),
    RegexPattern("SSH Private Key", re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"), "critical", "SSH private key"),
    RegexPattern("PGP Private Key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "critical", "PGP private key block"),
    RegexPattern("PostgreSQL URL", re.compile(r"postgresql://[^:]+:[^@]+@[^/]+/[^?\s]+"), "high", "PostgreSQL connection URL with credentials"),
    RegexPattern("MySQL URL", re.compile(r"mysql://[^:]+:[^@]+@[^/]+/[^?\s]+"), "high", "MySQL connection URL with credentials"),
    RegexPattern("MongoDB URL", re.compile(r"mongodb://[^:]+:[^@]+@[^/]+/[^?\s]+"), "high", "MongoDB connection URL with credentials"),
    RegexPattern("Redis URL", re.compile(r"redis://[^:]+:[^@]+@[^/]+:\d+"), "high", "Redis connection URL with credentials"),
    RegexPattern("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "high", "JSON Web Token"),
    RegexPattern("NPM Token", re.compile(r"npm_[A-Za-z0-9]{36}"), "high", "NPM access token"),
    RegexPattern("PyPI Token", re.compile(r"pypi-[A-Za-z0-9]{32}"), "high", "PyPI API token"),
    RegexPattern("Bearer Token (in code)", re.compile(r"Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"), "high", "Bearer token in code"),
    RegexPattern("Private Key in Variable", re.compile(r"(?i)(private.key|private_key|PRIVATE_KEY)\s*=\s*[\"'].*[\"']"), "critical", "Private key assigned to variable"),
]


class RegexDetector:
    def __init__(self, custom_patterns: list[dict[str, Any]] | None = None) -> None:
        self.patterns = list(BUILTIN_PATTERNS)
        if custom_patterns:
            for cp in custom_patterns:
                self.patterns.append(RegexPattern(
                    name=cp.get("name", "custom"),
                    pattern=re.compile(cp["pattern"]),
                    severity=cp.get("severity", "medium"),
                    description=cp.get("description", ""),
                ))

    def scan_line(self, line: str, line_number: int, file_path: str, repo_name: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for p in self.patterns:
            for match in p.pattern.finditer(line):
                results.append({
                    "repository": repo_name,
                    "file_path": file_path,
                    "line_number": line_number,
                    "secret_type": p.name,
                    "detection_method": "regex",
                    "severity": p.severity,
                    "confidence": 1.0,
                    "full_value": match.group(0),
                    "context_line": line.strip(),
                })
        return results
