from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")
DEFAULT_CONFIG_PATHS = [
    Path.home() / ".deep-scout" / "config.yaml",
    Path.cwd() / ".deep-scout.yaml",
]


def _resolve_env_vars(value: Any, seen: set[str] | None = None) -> Any:
    if seen is None:
        seen = set()
    if isinstance(value, str):
        def _replace(m: re.Match) -> str:
            var_name = m.group(1)
            if var_name in seen:
                return m.group(0)
            seen.add(var_name)
            resolved = os.environ.get(var_name, m.group(0))
            if isinstance(resolved, str):
                resolved = _resolve_env_vars(resolved, seen)
            return resolved
        return ENV_VAR_RE.sub(_replace, value)
    if isinstance(value, dict):
        return {k: _resolve_env_vars(v, seen) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_vars(v, seen) for v in value]
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


DEFAULT_CONFIG: dict[str, Any] = {
    "github": {
        "token": "${GITHUB_TOKEN}",
        "base_url": "https://api.github.com",
        "timeout_seconds": 30,
        "max_retries": 3,
        "retry_backoff_factor": 2,
    },
    "scanning": {
        "max_commit_depth": 100,
        "max_file_size_mb": 5,
        "max_repo_size_mb": 500,
        "exclude_repos": [],
        "exclude_paths": [
            "**/node_modules/**",
            "**/*.min.js",
            "**/vendor/**",
            "**/dist/**",
            "**/build/**",
            "**/__pycache__/**",
            "**/.git/**",
            "**/*.log",
            "**/*.lock",
        ],
        "include_paths": [],
        "scan_extensions": [
            ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
            ".json", ".yaml", ".yml", ".toml", ".ini", ".env",
            ".sh", ".bash", ".zsh", ".txt", ".md", ".cfg", ".conf",
            ".xml", ".pem", ".key", ".crt",
        ],
    },
    "detection": {
        "enable_regex": True,
        "enable_entropy": True,
        "enable_context_analysis": True,
        "entropy_threshold": 4.5,
        "min_secret_length": 16,
        "max_secret_length": 256,
        "context_keywords": [
            "key", "secret", "token", "password", "auth", "credential",
            "api_key", "apikey", "private_key", "privatekey",
            "access_key", "secret_key", "jwt", "bearer", "authorization",
        ],
        "custom_patterns": [],
        "custom_whitelist": [],
    },
    "reporting": {
        "default_format": "html",
        "output_dir": "./deep-scout-reports",
        "include_context_lines": 3,
        "mask_secrets_in_report": True,
    },
    "performance": {
        "parallel_workers": 0,
        "parallel_repos": 3,
        "cache_enabled": True,
        "cache_ttl_hours": 24,
        "cache_dir": str(Path.home() / ".deep-scout" / "cache"),
        "github_requests_per_second": 10,
    },
}


def load_config(paths: list[Path] | None = None, strict: bool = False) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)

    if paths is None:
        paths = DEFAULT_CONFIG_PATHS

    for path in paths:
        if path and path.exists():
            if strict and path != Path.home() / ".deep-scout" / "config.yaml":
                continue
            with open(path) as f:
                raw = yaml.safe_load(f)
            if isinstance(raw, dict):
                raw = _resolve_env_vars(raw)
                config = _deep_merge(config, raw)

    return config


def loaded_project_config() -> bool:
    project_path = Path.cwd() / ".deep-scout.yaml"
    return project_path.exists()
