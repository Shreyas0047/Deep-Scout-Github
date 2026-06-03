from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Any


class WhitelistEntry:
    def __init__(self, pattern: str, reason: str = "", entry_type: str = "regex"):
        self.pattern = pattern
        self.reason = reason
        self.entry_type = entry_type
        if entry_type == "regex":
            self._regex = re.compile(pattern)
        else:
            self._regex = None

    def matches(self, value: str) -> bool:
        if self.entry_type == "regex":
            return bool(self._regex and self._regex.search(value))
        if self.entry_type == "exact":
            return value == self.pattern
        if self.entry_type == "path":
            return fnmatch(value, self.pattern)
        return value == self.pattern


_BUILTIN_RULES: list[dict[str, str]] = [
    {"pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "reason": "UUID v4", "type": "regex"},
    {"pattern": r"\b[0-9a-f]{40}\b", "reason": "Git commit hash (SHA-1)", "type": "regex"},
    {"pattern": r"\b[0-9a-f]{64}\b", "reason": "Git commit hash (SHA-256)", "type": "regex"},
    {"pattern": "AKIAIOSFODNN7EXAMPLE", "reason": "AWS example key from documentation", "type": "exact"},
    {"pattern": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "reason": "AWS example secret key from documentation", "type": "exact"},
    {"pattern": r"\$\{[A-Z_]+\}", "reason": "Environment variable reference (${VAR})", "type": "regex"},
    {"pattern": r"\$[A-Z_][A-Z0-9_]+", "reason": "Environment variable reference ($VAR)", "type": "regex"},
    {"pattern": "sk_test_REPLACE_ME", "reason": "Stripe test key from documentation", "type": "exact"},  # pragma: allowlist secret
    {"pattern": r"localhost", "reason": "Localhost URL (cannot be accessed externally)", "type": "regex"},
    {"pattern": r"\b[0-9a-f]{12}\b", "reason": "Docker container ID", "type": "regex"},
    {"pattern": r"test[a-z0-9_]*", "reason": "Test data pattern", "type": "regex"},
]


class Whitelist:
    def __init__(self, custom_rules: list[dict[str, Any]] | None = None):
        self.entries: list[WhitelistEntry] = []
        for rule in _BUILTIN_RULES:
            self.entries.append(WhitelistEntry(rule["pattern"], rule["reason"], rule["type"]))
        if custom_rules:
            for rule in custom_rules:
                self.entries.append(WhitelistEntry(
                    pattern=rule.get("pattern") or rule.get("exact", ""),
                    reason=rule.get("reason", ""),
                    entry_type=rule.get("type", "exact"),
                ))

    def is_whitelisted(self, value: str, file_path: str = "") -> bool:
        for entry in self.entries:
            if entry.entry_type == "path":
                if file_path and entry.matches(file_path):
                    return True
            elif entry.matches(value):
                return True
        return False

    def filter_findings(self, findings: list[dict], file_path: str = "") -> list[dict]:
        return [f for f in findings if not self.is_whitelisted(f.get("full_value", ""), file_path or f.get("file_path", ""))]
