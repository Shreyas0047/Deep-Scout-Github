from __future__ import annotations

from typing import Any

import requests

from deep_scout.reporting.base import Finding


def build_slack_payload(findings: list[Finding], org: str) -> dict[str, Any]:
    if not findings:
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "✅ Deep-Scout: No secrets found", "emoji": True},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Organization:* {org}\nNo secrets were detected."},
                },
            ]
        }

    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔐 Deep-Scout GitHub: Credentials Found!", "emoji": True},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Organization:*\n{org}"},
                {"type": "mrkdwn", "text": f"*Secrets Found:*\n{len(findings)} ({critical_count} critical, {high_count} high)"},
            ],
        },
        {"type": "divider"},
    ]

    critical_high = [f for f in findings if f.severity in ("critical", "high")]

    for f in critical_high[:8]:
        emoji = "🚨" if f.severity == "critical" else "⚠️"

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{emoji} *{f.severity.upper()}: {f.secret_type}*"},
        })
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Repository:*\n{f.repository}"},
                {"type": "mrkdwn", "text": f"*File:*\n`{f.file_path}:{f.line_number}`"},
            ],
        })

        if f.remediation:
            steps_text = "\n".join(f.remediation.immediate_steps[:3])
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"*Remediation:*\n{steps_text}\n_Confidence: {f.confidence}_"}],
            })
            if f.remediation.revoke_urls:
                btn_elements = []
                for url in f.remediation.revoke_urls:
                    btn_elements.append({
                        "type": "button",
                        "text": {"type": "plain_text", "text": f"Revoke at {url.split('//')[1].split('/')[0]}", "emoji": True},
                        "url": url,
                        "style": "danger" if f.severity == "critical" else "primary",
                    })
                blocks.append({
                    "type": "actions",
                    "elements": btn_elements,
                })

    remaining = len(findings) - len(critical_high[:8])
    if remaining > 0:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"...and {remaining} more finding(s). Run `deep-scout scan --org {org} --format html` for full report."},
        })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": "Deep-Scout GitHub v1.0.0"}],
    })

    return {"blocks": blocks}


def send_slack_notification(webhook_url: str, payload: dict[str, Any]):
    resp = requests.post(webhook_url, json=payload, timeout=15)
    resp.raise_for_status()
