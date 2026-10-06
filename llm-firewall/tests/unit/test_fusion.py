"""Tests for firewall.detection.fusion."""

from __future__ import annotations

import pytest

from firewall.config import BlockingMode
from firewall.detection.fusion import FusionInput, fuse
from firewall.detection.verdict import Action


def _fi(regex: float = 0.0, cls: float | None = 0.0, signals: int = 0) -> FusionInput:
    return FusionInput(regex_max_severity=regex, classifier_prob=cls, evasion_signal_count=signals)


def test_worst_of_both_dominates_regex() -> None:
    out = fuse(_fi(regex=0.9, cls=0.1), 0.8, 0.5, BlockingMode.HARD_BLOCK)
    assert out.risk_score == 0.9
    assert out.action is Action.BLOCK
    assert not out.allowed


def test_worst_of_both_dominates_classifier() -> None:
    out = fuse(_fi(regex=0.1, cls=0.9), 0.8, 0.5, BlockingMode.HARD_BLOCK)
    assert out.risk_score == 0.9
    assert out.action is Action.BLOCK


def test_warn_band() -> None:
    out = fuse(_fi(regex=0.6, cls=0.5), 0.8, 0.5, BlockingMode.HARD_BLOCK)
    assert out.action is Action.WARN
    assert out.allowed  # warn is not a block


def test_allow_band() -> None:
    out = fuse(_fi(regex=0.3, cls=0.2), 0.8, 0.5, BlockingMode.HARD_BLOCK)
    assert out.action is Action.ALLOW
    assert out.allowed


def test_evasion_bonus_can_push_over_block() -> None:
    # 0.6 regex + 3 evasion signals (=0.30 bonus) -> 0.9 >= block.
    out = fuse(_fi(regex=0.6, cls=0.0, signals=3), 0.8, 0.5, BlockingMode.HARD_BLOCK)
    assert out.action is Action.BLOCK


def test_evasion_bonus_capped() -> None:
    # 10 signals should not exceed the 0.30 cap.
    out = fuse(_fi(regex=0.0, cls=0.0, signals=10), 0.8, 0.5, BlockingMode.HARD_BLOCK)
    assert out.risk_score == pytest.approx(0.30)


def test_classifier_none_treated_as_zero() -> None:
    # Degraded classifier: no dilution, no penalty.
    out = fuse(_fi(regex=0.9, cls=None), 0.8, 0.5, BlockingMode.HARD_BLOCK)
    assert out.risk_score == 0.9
    assert out.action is Action.BLOCK


def test_soft_warn_mode_downgrades_block() -> None:
    out = fuse(_fi(regex=0.9), 0.8, 0.5, BlockingMode.SOFT_WARN)
    assert out.action is Action.WARN
    assert out.allowed  # allowed through even though nominally a block


def test_shadow_mode_always_allows() -> None:
    out = fuse(_fi(regex=1.0), 0.8, 0.5, BlockingMode.SHADOW)
    assert out.allowed
    assert out.action is Action.ALLOW


def test_invalid_thresholds_rejected() -> None:
    with pytest.raises(ValueError):
        fuse(_fi(regex=0.5), block_threshold=0.5, warn_threshold=0.5, mode=BlockingMode.HARD_BLOCK)
    with pytest.raises(ValueError):
        fuse(_fi(regex=0.5), block_threshold=1.2, warn_threshold=0.5, mode=BlockingMode.HARD_BLOCK)


def test_risk_score_capped_at_one() -> None:
    out = fuse(_fi(regex=0.95, cls=0.9, signals=10), 0.8, 0.5, BlockingMode.HARD_BLOCK)
    assert out.risk_score == 1.0
