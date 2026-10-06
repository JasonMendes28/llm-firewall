"""Egress response guardrail and leak-detection layer.

Inspects upstream LLM responses before delivery to the client.
Protects against:
1. System prompt & confidential instruction exfiltration.
2. High-entropy credentials & secrets leakage (AWS keys, private keys, API tokens).
3. Configured canary token disclosure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Patterns for sensitive credentials & secrets
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"\b(?:sk-ant-|sk-[a-zA-Z0-9_-]{24,})\b")),
]

# Patterns indicating system prompt or internal guideline exfiltration
_EXFIL_INDICATORS: list[tuple[str, re.Pattern[str]]] = [
    (
        "system_prompt_dump",
        re.compile(
            r"\b(?:here\s+(?:is|are)\s+(?:my|the)\s+(?:original\s+|initial\s+)?(?:system\s+prompt|system\s+instructions?)|"
            r"my\s+(?:system\s+prompt|initial\s+instructions?)\s+(?:is|was|were|states?)\s*:)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "confidential_rules_dump",
        re.compile(
            r"\b(?:confidential\s+system\s+instructions|internal\s+safety\s+guidelines\s+follow)\b",
            re.IGNORECASE,
        ),
    ),
]


@dataclass(frozen=True, slots=True)
class EgressVerdict:
    """Outcome of egress content scanning."""

    allowed: bool
    violations: list[str] = field(default_factory=list)
    action: str = "allow"  # "allow" | "block"


class EgressScanner:
    """Scans upstream responses for leaked system prompts, secrets, and canary tokens."""

    def __init__(self, canary_tokens: list[str] | None = None) -> None:
        """Initialize the scanner.

        Args:
            canary_tokens: Optional list of confidential canary tokens to watch for.
        """
        self._canaries = [c.strip() for c in (canary_tokens or []) if c.strip()]

    def scan(self, response_text: str) -> EgressVerdict:
        """Inspect model output text for policy violations.

        Args:
            response_text: Raw text emitted by the upstream model.

        Returns:
            EgressVerdict indicating whether output is allowed to be returned.
        """
        violations: list[str] = []

        # 1. Canary tokens check
        for canary in self._canaries:
            if canary in response_text:
                violations.append(f"canary_token_detected:{canary[:4]}***")

        # 2. Secret / credential leaks check
        for name, pattern in _SECRET_PATTERNS:
            if pattern.search(response_text):
                violations.append(name)

        # 3. System prompt exfiltration indicators
        for name, pattern in _EXFIL_INDICATORS:
            if pattern.search(response_text):
                violations.append(name)

        if violations:
            return EgressVerdict(
                allowed=False,
                violations=violations,
                action="block",
            )

        return EgressVerdict(allowed=True, violations=[], action="allow")
