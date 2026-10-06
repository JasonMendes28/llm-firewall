"""Audit logger for verdict events.

Design contract (ADR-003):
- Default output: verdict metadata only (hash, length, rule IDs, score, action).
  NEVER the raw prompt.
- Opt-in `LOG_FULL_PROMPTS=true` adds the raw prompt, but ONLY for prompts that
  triggered a rule (block or warn). Clean traffic is never logged in plaintext.
- No database in v1. Structured JSON to stdout goes to your log aggregator.
"""

from __future__ import annotations

from firewall.detection.verdict import Action, Verdict
from firewall.logging_setup import get_logger


class AuditLogger:
    """Emits one structured log event per verdict."""

    def __init__(self, log_full_prompts: bool) -> None:
        """Initialize the audit logger.

        Args:
            log_full_prompts: If True, prompts that produced a warn/block
                verdict are logged in plaintext under a `prompt_plaintext` key.
                Clean allows are still logged as hash-only regardless.
        """
        self._log_full_prompts = log_full_prompts
        self._log = get_logger("audit")

    def record(self, verdict: Verdict, prompt_plaintext: str | None) -> None:
        """Emit an audit event for a verdict.

        Args:
            verdict: The immutable verdict produced by the detection pipeline.
            prompt_plaintext: The raw prompt. Included in the log ONLY when
                (a) `log_full_prompts` is True AND (b) verdict.action_taken is
                warn or block. Callers may pass None to skip plaintext entirely.
        """
        # Note: structlog reserves the first positional arg (a.k.a. `event`) as
        # the log message key. We pass `"verdict"` positionally and everything
        # else as keyword fields; do NOT put a key literally named `event` in
        # the fields dict or structlog raises `multiple values for 'event'`.
        fields: dict[str, object] = {
            "request_id": verdict.request_id,
            "allowed": verdict.allowed,
            "action": verdict.action_taken.value,
            "risk_score": verdict.risk_score,
            "classifier_confidence": verdict.classifier_confidence,
            "matched_rule_ids": verdict.matched_rule_ids,
            "mode": verdict.mode,
            "degraded": verdict.degraded,
            "prompt_hash": verdict.prompt_hash,
            "prompt_length": verdict.prompt_length,
            "timestamp": verdict.timestamp,
        }
        if (
            self._log_full_prompts
            and prompt_plaintext is not None
            and verdict.action_taken in (Action.WARN, Action.BLOCK)
        ):
            fields["prompt_plaintext"] = prompt_plaintext

        self._log.info("verdict", **fields)
