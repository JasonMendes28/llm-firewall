"""Fusion layer: combine regex + classifier scores and produce a routing decision.

Formula (ADR-012):

    base_score = max(regex_max_severity, classifier_prob or 0.0)
    risk_score = min(1.0, base_score + evasion_bonus)

Rationale:
- max() (worst-of-both) prevents a confident regex hit from being diluted by a
  low classifier score. Averaging would let attackers craft prompts that trip
  regex but look benign to the classifier.
- Evasion signals from the normalizer contribute a small additive bonus,
  capped, so heavy obfuscation (zero-width chars + base64 + homoglyphs) pushes
  a borderline score over the warn/block threshold without dominating on its own.
- If the classifier is degraded, we don't punish the request for it — we set
  classifier_prob to None and let regex + evasion signals speak for themselves,
  and the verdict carries `degraded=true` so operators know.
"""

from __future__ import annotations

from dataclasses import dataclass

from firewall.config import BlockingMode
from firewall.detection.verdict import Action

# Each distinct evasion signal contributes this much, capped by _MAX_EVASION_BONUS.
# Values chosen so that 3+ concurrent signals reach 0.30, which is enough to
# push a mid-confidence regex/classifier hit over a 0.80 block threshold but not
# enough to block on evasion signals alone.
_EVASION_SIGNAL_WEIGHT = 0.10
_MAX_EVASION_BONUS = 0.30


@dataclass(frozen=True, slots=True)
class FusionInput:
    """Everything the fusion layer needs from upstream detection stages."""

    regex_max_severity: float
    classifier_prob: float | None  # None iff classifier was unavailable
    evasion_signal_count: int


@dataclass(frozen=True, slots=True)
class FusionOutput:
    """Fusion decision, ready to be attached to a Verdict."""

    risk_score: float
    action: Action
    allowed: bool


def fuse(
    fusion_input: FusionInput,
    block_threshold: float,
    warn_threshold: float,
    mode: BlockingMode,
) -> FusionOutput:
    """Combine detection scores and route to an action.

    Args:
        fusion_input: The upstream scores plus evasion signal count.
        block_threshold: risk_score >= this -> block (in hard_block mode).
        warn_threshold: risk_score >= this and < block_threshold -> warn.
        mode: The active blocking mode (hard_block, soft_warn, shadow).

    Returns:
        FusionOutput with the fused risk_score, chosen Action, and the
        `allowed` flag reflecting the *effective* decision after mode is applied.

    Raises:
        ValueError: If thresholds are inconsistent. We check here as a
            belt-and-suspenders complement to Settings-level validation; a
            corrupted or manually-overridden config should still fail loudly.
    """
    if not 0.0 <= warn_threshold < block_threshold <= 1.0:
        raise ValueError(f"Invalid thresholds: warn={warn_threshold}, block={block_threshold}")

    classifier_component = fusion_input.classifier_prob or 0.0
    base_score = max(fusion_input.regex_max_severity, classifier_component)

    evasion_bonus = min(
        _MAX_EVASION_BONUS,
        fusion_input.evasion_signal_count * _EVASION_SIGNAL_WEIGHT,
    )
    risk_score = min(1.0, base_score + evasion_bonus)

    # Decide the *nominal* action from the score.
    if risk_score >= block_threshold:
        nominal = Action.BLOCK
    elif risk_score >= warn_threshold:
        nominal = Action.WARN
    else:
        nominal = Action.ALLOW

    # Apply the mode. Detection logic is identical across modes — only the
    # externally-observable action changes. This is what enables "shadow mode"
    # to be a truly non-behavioral rollout.
    if mode is BlockingMode.HARD_BLOCK:
        action = nominal
        allowed = nominal is not Action.BLOCK
    elif mode is BlockingMode.SOFT_WARN:
        # Blocks are downgraded to warnings; requests still flow.
        action = Action.WARN if nominal is Action.BLOCK else nominal
        allowed = True
    elif mode is BlockingMode.SHADOW:
        # Everything is allowed; the nominal action is only for logs.
        action = Action.ALLOW
        allowed = True
    else:  # pragma: no cover — enum exhaustiveness safeguard
        raise ValueError(f"unknown blocking mode: {mode}")

    return FusionOutput(risk_score=risk_score, action=action, allowed=allowed)
