from __future__ import annotations

import math
import re
from typing import Any

CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_.\-]{16,256}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


_CONTEXT_KEYWORDS = [
    "key", "secret", "token", "password", "auth", "credential",
    "api_key", "apikey", "private_key", "privatekey",
    "access_key", "secret_key", "jwt", "bearer", "authorization",
]


def _scan_line_for_context(line: str) -> float:
    lower = line.lower()
    boost = 0.0
    for kw in _CONTEXT_KEYWORDS:
        if kw in lower:
            boost = max(boost, 0.4)
            break
    if "=" in lower or ":" in lower:
        boost = max(boost, 0.2)
    return boost


class EntropyDetector:
    def __init__(
        self,
        threshold: float = 4.5,
        min_length: int = 16,
        max_length: int = 256,
        enable_context_analysis: bool = True,
    ) -> None:
        self.threshold = threshold
        self.min_length = min_length
        self.max_length = max_length
        self.enable_context_analysis = enable_context_analysis

    def scan_line(self, line: str, line_number: int, file_path: str, repo_name: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for match in CANDIDATE_RE.finditer(line):
            candidate = match.group(0)
            if len(candidate) < self.min_length:
                continue
            if len(candidate) > self.max_length:
                candidate = candidate[:self.max_length]

            entropy = shannon_entropy(candidate)
            if entropy < self.threshold:
                continue

            confidence = 0.6
            if self.enable_context_analysis:
                confidence += _scan_line_for_context(line)

            results.append({
                "repository": repo_name,
                "file_path": file_path,
                "line_number": line_number,
                "secret_type": "High-Entropy String",
                "detection_method": "entropy",
                "severity": "medium",
                "confidence": min(confidence, 1.0),
                "full_value": candidate,
                "entropy": round(entropy, 2),
                "context_line": line.strip(),
            })
        return results
