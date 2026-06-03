# Contributing to Deep-Scout

Thanks for your interest in contributing! This guide will help you get started.

## Code of Conduct

Be respectful, constructive, and inclusive. We're all here to make secret scanning better.

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/yourusername/deep-scout-github/issues) with:

- Deep-Scout version (`deep-scout --version`)
- Python version and OS
- Steps to reproduce
- Expected vs actual behavior
- Relevant error output (redact any secrets)

### Suggesting Features

Open a [GitHub Issue](https://github.com/yourusername/deep-scout-github/issues) with:

- Clear description of the problem you're solving
- Proposed solution or approach
- Why this would benefit the community

### Adding Secret Patterns

The easiest way to contribute! Open a PR that adds to `deep_scout/detectors/regex.py`:

```python
RegexPattern("Your Service Key", re.compile(r"your_regex_pattern"), "high", "description"),
```

Requirements:
- Pattern must be tested against known examples
- Severity must be: `critical`, `high`, `medium`, or `low`
- Avoid overly broad patterns that generate false positives

### Improving Remediation

Add or update entries in `deep_scout/reporting/remediation.py`:

```python
"Your Service Key": RemediationInfo(
    risk="What an attacker can do",
    severity_reason="Why this is serious",
    immediate_steps=["1. First step", "2. Second step"],
    revoke_urls=["https://console.service.com/revoke"],
    git_cleanup_command="bfg --replace-text secrets.txt <repo>.git",
    prevention_tips=["Tip 1", "Tip 2"],
),
```

## Development Setup

```bash
git clone https://github.com/yourusername/deep-scout-github
cd deep-scout-github
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=deep_scout

# Lint & type check
ruff check .
mypy deep_scout/
```

## Pull Request Process

1. Fork the repo and create a feature branch (`git checkout -b feat/my-feature`)
2. Make your changes — keep them focused and well-tested
3. Run the test suite and ensure it passes
4. Update documentation if needed (README, CLI help text)
5. Open a PR against `main` with a clear description

## Project Structure

```
deep_scout/
  cli.py              # Click CLI commands
  config.py           # YAML config loader
  scanner.py          # Scan orchestrator
  github/client.py    # GitHub API client
  detectors/
    regex.py          # Regex detection patterns
    entropy.py        # Shannon entropy analysis
  reporting/
    base.py           # Finding dataclass
    html.py           # HTML report generator
    json_report.py    # JSON report generator
    slack.py          # Slack notification
    remediation.py    # Remediation guide data
  ui/progress.py      # Live terminal progress
  utils/
    whitelist.py      # False positive filtering
    file_walker.py    # File discovery & filtering
    git.py            # Git clone utilities
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
