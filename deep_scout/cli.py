import importlib.resources
import os
import shutil
import threading
import time
from pathlib import Path

import click

from deep_scout.config import load_config, loaded_project_config
from deep_scout.detectors.entropy import shannon_entropy
from deep_scout.reporting.html import build_html_report, write_html_report
from deep_scout.reporting.json_report import build_report, write_json_report
from deep_scout.reporting.slack import build_slack_payload, send_slack_notification
from deep_scout.scanner import Scanner
from deep_scout.ui.progress import ScanProgress, run_progress_display
from deep_scout.utils.whitelist import _BUILTIN_RULES


@click.group()
@click.version_option(version="1.0.0", prog_name="deep-scout")
def cli():
    """Deep-Scout GitHub — deep reconnaissance for secrets in GitHub organizations."""


@cli.command()
@click.option("--org", required=True, help="GitHub organization or username to scan")
@click.option("--repo", help="Specific repository to scan (scans all repos in org if omitted)")
@click.option("--depth", default=100, show_default=True, help="Number of commits to clone")
@click.option("--entropy-threshold", default=4.5, show_default=True, help="Shannon entropy threshold (bits/byte)")
@click.option("--output", default="./deep-scout-reports", show_default=True, help="Output directory")
@click.option("--format", "output_format", default="html", show_default=True, type=click.Choice(["html", "json", "slack"]))
@click.option("--fail-on-secret", is_flag=True, help="Exit with code 1 if secrets are found")
@click.option("--no-entropy", is_flag=True, help="Disable entropy detection")
@click.option("--no-regex", is_flag=True, help="Disable regex detection")
@click.option("--strict", is_flag=True, help="Ignore project-level config files (use only ~/.deep-scout/config.yaml)")
def scan(org, repo, depth, entropy_threshold, output, output_format, fail_on_secret, no_entropy, no_regex, strict):
    """Scan a GitHub organization for accidentally committed secrets."""
    if loaded_project_config():
        if strict:
            click.echo("⚠  Project-level .deep-scout.yaml detected but ignored (--strict mode).")
        else:
            click.echo("⚠  Project-level .deep-scout.yaml detected. Use --strict to ignore untrusted config files.")

    config = load_config(strict=strict)
    config["detection"]["entropy_threshold"] = entropy_threshold
    config["scanning"]["max_commit_depth"] = depth
    if no_entropy:
        config["detection"]["enable_entropy"] = False
    if no_regex:
        config["detection"]["enable_regex"] = False

    if not os.environ.get("GITHUB_TOKEN"):
        click.echo("❌ GITHUB_TOKEN environment variable is not set.", err=True)
        raise SystemExit(2)

    scanner = Scanner(config)

    remaining, reset_time = scanner.client.check_rate_limit()
    authenticated_user = ""
    try:
        user_resp = scanner.client.get("/user")
        authenticated_user = user_resp.json().get("login", "")
    except Exception:
        pass

    repos = scanner.client.list_organization_repos(org)
    scanning_config = config["scanning"]
    exclude_patterns = scanning_config.get("exclude_repos", [])
    filtered_repos = [r for r in repos if not r.is_archived and not any(Path(r.name).match(p) for p in exclude_patterns)]
    if repo:
        filtered_repos = [r for r in filtered_repos if r.name == repo]

    total_repo_count = len(filtered_repos)
    if total_repo_count == 0:
        click.echo("No repositories to scan after filtering.")
        return

    progress = ScanProgress(org, total_repo_count)

    findings: list = []
    exception: list[Exception] = []
    start_ts = time.monotonic()

    def _run_scan():
        try:
            result = scanner.scan_org(org, repo_filter=repo, progress=progress)
            findings.extend(result)
        except Exception as e:
            exception.append(e)

    scan_thread = threading.Thread(target=_run_scan, daemon=True)
    scan_thread.start()

    run_progress_display(
        progress,
        rate_limit_remaining=remaining,
        rate_limit_total=5000,
        authenticated_user=authenticated_user,
    )

    scan_thread.join()
    duration = time.monotonic() - start_ts

    if exception:
        raise click.ClickException(str(exception[0]))

    os.makedirs(output, exist_ok=True)

    if output_format == "html":
        html = build_html_report(findings, org, duration)
        out_path = os.path.join(output, f"deep-scout-report-{org}.html")
        write_html_report(html, out_path)
        click.echo(f"✅ HTML report saved to: {out_path}")

    elif output_format == "json":
        report = build_report(findings, org, duration)
        out_path = os.path.join(output, f"deep-scout-report-{org}.json")
        write_json_report(report, out_path)
        click.echo(f"✅ JSON report saved to: {out_path}")

    elif output_format == "slack":
        webhook = os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook:
            click.echo("❌ SLACK_WEBHOOK_URL environment variable is not set.", err=True)
            raise SystemExit(4)
        payload = build_slack_payload(findings, org)
        send_slack_notification(webhook, payload)
        click.echo("✅ Slack notification sent.")

    click.echo(f"   Found {len(findings)} secret(s)")

    if findings:
        click.echo("   Severity breakdown:")
        for sev in ["critical", "high", "medium", "low"]:
            count = sum(1 for f in findings if f.severity == sev)
            if count:
                click.echo(f"     {sev}: {count}")

        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        if critical_high:
            click.echo()
            _print_remediation_summary(critical_high)

        if fail_on_secret:
            raise SystemExit(1)
    else:
        click.echo("   No secrets found. ✅")


def _print_remediation_summary(findings: list[Finding]):
    click.echo("━" * 60)
    click.echo("  🚨 CRITICAL & HIGH FINDINGS — Immediate Action Required")
    click.echo("━" * 60)

    grouped: dict[str, dict] = {}
    for f in findings:
        key = f.secret_type
        if key not in grouped:
            grouped[key] = {"severity": f.severity, "repos": set(), "remediation": f.remediation}
        grouped[key]["repos"].add(f.repository)

    for secret_type, info in grouped.items():
        emoji = "🚨" if info["severity"] == "critical" else "⚠️"
        click.echo(f"\n  {emoji} {secret_type} ({info['severity'].upper()})")
        click.echo(f"     Repos: {', '.join(sorted(info['repos']))}")
        if info["remediation"]:
            if info["remediation"].revoke_urls:
                for url in info["remediation"].revoke_urls:
                    if not url.startswith("N/A"):
                        click.echo(f"     → Revoke: {url}")
            first_step = info["remediation"].immediate_steps[0] if info["remediation"].immediate_steps else ""
            if first_step:
                click.echo(f"     → {first_step}")
    click.echo()


@cli.command()
@click.argument("string")
def entropy(string):
    """Calculate Shannon entropy of a given string."""
    e = shannon_entropy(string)
    label = "HIGH" if e >= 4.5 else ("MEDIUM" if e >= 3.5 else "LOW")
    click.echo(f"Entropy: {e:.2f} bits/byte — {label}")
    click.echo(f"Length: {len(string)} characters")


@cli.group()
def whitelist():
    """Manage whitelist patterns."""


@whitelist.command("list")
def whitelist_list():
    """Display all built-in and user-added whitelist patterns."""
    click.echo("Deep-Scout Whitelist (Built-in Patterns)")
    click.echo("━" * 60)
    for rule in _BUILTIN_RULES:
        click.echo(f"  {rule['reason']:45s} {rule['pattern'][:50]}")
    click.echo()
    click.echo("To add custom patterns, edit ~/.deep-scout/config.yaml or ./.deep-scout.yaml")


@whitelist.command()
@click.option("--pattern", required=True, help="Pattern to add")
@click.option("--reason", required=True, help="Explanation for why this is whitelisted")
def add(pattern, reason):
    """Add a custom whitelist entry."""
    config_path = Path.cwd() / ".deep-scout.yaml"
    if not config_path.exists():
        config_path = Path.home() / ".deep-scout" / "config.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

    import yaml

    if config_path.exists():
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    else:
        raw = {}

    raw.setdefault("detection", {}).setdefault("custom_whitelist", [])
    raw["detection"]["custom_whitelist"].append({"pattern": pattern, "reason": reason, "type": "regex"})

    with open(config_path, "w") as f:
        yaml.dump(raw, f, default_flow_style=False)

    click.echo(f"✅ Added whitelist pattern to {config_path}")


@whitelist.command()
@click.option("--pattern", required=True, help="Pattern to remove")
def remove(pattern):
    """Remove a custom whitelist entry."""
    config_path = Path.cwd() / ".deep-scout.yaml"
    if not config_path.exists():
        config_path = Path.home() / ".deep-scout" / "config.yaml"
    if not config_path.exists():
        click.echo("No config file found.", err=True)
        return

    import yaml

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    whitelist_entries = raw.get("detection", {}).get("custom_whitelist", [])
    before = len(whitelist_entries)
    raw["detection"]["custom_whitelist"] = [e for e in whitelist_entries if e.get("pattern") != pattern]

    if len(raw["detection"]["custom_whitelist"]) == before:
        click.echo("Pattern not found in custom whitelist.")
        return

    with open(config_path, "w") as f:
        yaml.dump(raw, f, default_flow_style=False)

    click.echo(f"✅ Removed whitelist pattern from {config_path}")


@cli.command("install-hook")
def install_hook():
    """Install the pre-commit git hook for secret scanning."""
    git_hooks_dir = Path.cwd() / ".git" / "hooks"
    if not git_hooks_dir.exists():
        click.echo("❌ Not a git repository. Run this command from the root of a git repo.", err=True)
        raise SystemExit(4)

    src = importlib.resources.files("deep_scout") / "hooks" / "pre-commit"
    dest = git_hooks_dir / "pre-commit"

    if not src.exists():
        s = """#!/bin/bash
echo "🔐 Deep-Scout pre-commit hook"
git diff --cached --name-only --diff-filter=ACM | xargs deep-scout scan --files-only --fail-on-secret 2>/dev/null
if [ $? -eq 1 ]; then echo "❌ Commit blocked: secrets found"; exit 1; fi
echo "✅ No secrets detected."
exit 0
"""
        dest.write_text(s)
    else:
        shutil.copy2(src, dest)

    dest.chmod(0o755)
    click.echo(f"✅ Pre-commit hook installed at {dest}")
