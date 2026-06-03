from dataclasses import dataclass, field
from typing import Optional

from deep_scout.reporting.remediation import RemediationInfo, get_remediation


@dataclass
class Finding:
    repository: str
    file_path: str
    line_number: int
    secret_type: str
    detection_method: str  # "regex" or "entropy"
    severity: str  # "critical", "high", "medium", "low"
    confidence: float  # 0.0 to 1.0
    value_preview: str        # partially masked
    full_value: str           # unmasked (used for dedup, not displayed by default)
    context_line: str = ""
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    commit_hash: Optional[str] = None
    commit_timestamp: Optional[str] = None
    author: Optional[str] = None
    remediation: Optional[RemediationInfo] = None
    remediation_url: Optional[str] = None

    def __post_init__(self):
        if self.remediation is None:
            self.remediation = get_remediation(self.secret_type)
