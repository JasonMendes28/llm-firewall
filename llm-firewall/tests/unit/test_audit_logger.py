"""Tests for firewall.audit.logger — PII handling contract."""

from __future__ import annotations

import io
import json

import structlog

from firewall.audit.logger import AuditLogger
from firewall.detection.verdict import Action, Verdict


def _make_verdict(action: Action = Action.ALLOW) -> Verdict:
    return Verdict(
        request_id="req-1",
        allowed=action is not Action.BLOCK,
        action_taken=action,
        risk_score=0.42,
        classifier_confidence=0.1,
        matched_rule_ids=[] if action is Action.ALLOW else ["R-X-001"],
        mode="hard_block",
        degraded=False,
        prompt_hash="sha256:deadbeef",
        prompt_length=42,
    )


def _capture(fn) -> list[dict]:
    """Reconfigure structlog to a buffer, invoke fn, return parsed events.

    We build the AuditLogger inside fn so its logger reference points at the
    reconfigured factory (structlog binds at logger-construction time when
    caching is on).
    """
    buf = io.StringIO()
    structlog.reset_defaults()
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=buf),
        cache_logger_on_first_use=False,
    )
    try:
        fn()
    finally:
        structlog.reset_defaults()
    lines = [line for line in buf.getvalue().splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def test_allow_never_logs_plaintext_even_when_enabled() -> None:
    """Even with full-prompt logging ON, benign 'allow' verdicts stay hash-only."""

    def _run() -> None:
        AuditLogger(log_full_prompts=True).record(_make_verdict(Action.ALLOW), "the plaintext")

    events = _capture(_run)
    assert len(events) == 1
    assert "prompt_plaintext" not in events[0]


def test_block_logs_plaintext_when_enabled() -> None:
    def _run() -> None:
        AuditLogger(log_full_prompts=True).record(_make_verdict(Action.BLOCK), "the plaintext")

    events = _capture(_run)
    assert events[0]["prompt_plaintext"] == "the plaintext"


def test_block_no_plaintext_when_disabled() -> None:
    def _run() -> None:
        AuditLogger(log_full_prompts=False).record(_make_verdict(Action.BLOCK), "the plaintext")

    events = _capture(_run)
    assert "prompt_plaintext" not in events[0]


def test_hash_and_length_always_present() -> None:
    def _run() -> None:
        AuditLogger(log_full_prompts=False).record(_make_verdict(Action.ALLOW), None)

    events = _capture(_run)
    assert events[0]["prompt_hash"] == "sha256:deadbeef"
    assert events[0]["prompt_length"] == 42
