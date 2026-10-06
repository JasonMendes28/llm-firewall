"""Verdict dataclass and serialization.

Schema locked in Stage 1:
- matched_rules exposes IDs only (no descriptions) to prevent detection-logic leaks.
- latency_ms is only populated when DEBUG_TIMING=true, to prevent side-channel
  inference of which detection layer triggered.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Action(StrEnum):
    """Concrete action taken on a request."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class LatencyBreakdown:
    """Per-layer timing. Only serialized when DEBUG_TIMING is enabled."""

    total_ms: float
    normalize_ms: float
    regex_ms: float
    classifier_ms: float
    fusion_ms: float


@dataclass(frozen=True, slots=True)
class Verdict:
    """Immutable verdict produced by the detection pipeline.

    Attributes:
        request_id: Correlation ID (UUID v4 string) for tying logs together.
        allowed: True iff the request should be forwarded to the upstream model.
        action_taken: The concrete action (allow/warn/block).
        risk_score: Fused risk in [0.0, 1.0]. 1.0 = maximum confidence adversarial.
        classifier_confidence: Raw classifier probability, or None if degraded.
        matched_rule_ids: List of regex rule IDs that fired. Descriptions are
            deliberately omitted to avoid leaking detection internals.
        mode: The blocking mode active when this verdict was rendered.
        degraded: True if the ML classifier was unavailable and we ran regex-only.
        prompt_hash: SHA-256 of the raw prompt. Enables correlation without content.
        prompt_length: Character count of the raw prompt.
        timestamp: ISO-8601 UTC.
        latency: Per-layer timing; only populated when DEBUG_TIMING is true.
    """

    request_id: str
    allowed: bool
    action_taken: Action
    risk_score: float
    classifier_confidence: float | None
    matched_rule_ids: list[str]
    mode: str
    degraded: bool
    prompt_hash: str
    prompt_length: int
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    latency: LatencyBreakdown | None = None

    def to_public_dict(self, include_timing: bool) -> dict[str, Any]:
        """Serialize for the API response.

        Args:
            include_timing: If False, drops the `latency` field. Should mirror
                the DEBUG_TIMING config so we don't leak per-layer timing in prod.

        Returns:
            JSON-serializable dict with the locked schema.
        """
        d = asdict(self)
        # Enum -> string.
        d["action_taken"] = self.action_taken.value
        if not include_timing:
            d.pop("latency", None)
        elif self.latency is not None:
            d["latency"] = asdict(self.latency)
        return d
