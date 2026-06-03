from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from deep_scout.reporting.base import Finding


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "repository": f.repository,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "secret_type": f.secret_type,
        "detection_method": f.detection_method,
        "severity": f.severity,
        "confidence": f.confidence,
        "preview": f.value_preview,
        "context": f.context_line.strip() if f.context_line else "",
    }

    if f.remediation:
        result["remediation"] = {
            "risk": f.remediation.risk,
            "immediate_steps": f.remediation.immediate_steps,
            "revoke_urls": f.remediation.revoke_urls,
            "git_cleanup_command": f.remediation.git_cleanup_command,
            "prevention_tips": f.remediation.prevention_tips,
        }

    return result


def build_report(findings: list[Finding], org: str, scan_duration: float) -> dict[str, Any]:
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_type: dict[str, int] = {}

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.secret_type] = by_type.get(f.secret_type, 0) + 1

    report = {
        "tool": "deep-scout-github",
        "version": "1.0.0",
        "scan_id": f"ds-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{abs(hash(str(findings))):x}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "organization": org,
        "duration_seconds": round(scan_duration, 2),
        "total_findings": len(findings),
        "findings": [_finding_to_dict(f) for f in findings],
        "summary": {
            "by_severity": by_severity,
            "by_type": by_type,
        },
    }
    return report


def write_json_report(report: dict[str, Any], output_path: str, indent: int = 2):
    with open(output_path, "w") as f:
        json.dump(report, f, indent=indent)
