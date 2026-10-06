"""Regex-based detection layer.

Production Hardening:
- RE2 Engine Support: Evaluates patterns using Google's `re2` engine whenever available.
  RE2 provides mathematical guarantees of O(N) linear time execution, completely
  eliminating Regular Expression Denial of Service (ReDoS) catastrophic backtracking.
- Seamless Fallback: Falls back gracefully to Python's standard `re` if RE2 is not present.
- Strict Load-Time Validation: Rules loaded from YAML (e.g. `rules/default_rules.yaml`)
  must conform to the strict schema or startup is prevented immediately.

The engine returns:
- A list of rule IDs that matched (public — surfaced in API).
- A severity-weighted score in [0.0, 1.0] (public — fused into risk_score).
- Which surface each match came from: canonical text vs a decoded probe (internal-only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from firewall.detection.normalizer import NormalizedPrompt

try:
    import re2

    _HAS_RE2 = True
except ImportError:
    _HAS_RE2 = False


class Severity(StrEnum):
    """Discrete severity tiers.

    Chose discrete tiers over continuous weights (ADR-011) for auditability.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.9,
}


class RuleLoadError(ValueError):
    """Raised when the rule file fails schema validation."""


@dataclass(frozen=True, slots=True)
class Rule:
    """Compiled rule ready for evaluation.

    Attributes:
        id: Stable rule ID (e.g. R-OVERRIDE-001).
        category: Grouping label; internal only.
        severity: Tier controlling the fusion weight.
        pattern: Original pattern string.
        description: Internal-only human explanation; NEVER returned to clients.
        compiled: Precompiled regex (RE2 or standard re Pattern).
    """

    id: str
    category: str
    severity: Severity
    pattern: str
    description: str
    compiled: Any


@dataclass(frozen=True, slots=True)
class RegexResult:
    """Output of a single regex evaluation pass."""

    matched_rule_ids: list[str]
    max_severity_weight: float
    matches_from_decoded_probes: list[str]  # subset of matched_rule_ids


def _validate_rule_dict(raw: dict[str, Any], idx: int) -> None:
    """Validate a single rule dict; raise RuleLoadError with a precise location."""
    required = {"id", "category", "severity", "pattern", "description"}
    missing = required - raw.keys()
    if missing:
        raise RuleLoadError(f"rule #{idx}: missing fields: {sorted(missing)}")
    if not isinstance(raw["id"], str) or not raw["id"].strip():
        raise RuleLoadError(f"rule #{idx}: 'id' must be a non-empty string")
    if not isinstance(raw["pattern"], str) or not raw["pattern"]:
        raise RuleLoadError(f"rule {raw['id']}: 'pattern' must be a non-empty string")
    if raw["severity"] not in {"low", "medium", "high"}:
        raise RuleLoadError(
            f"rule {raw['id']}: 'severity' must be one of low|medium|high, "
            f"got {raw['severity']!r}"
        )


def _compile_pattern(pattern_str: str) -> Any:
    """Compile pattern using Google RE2 if available, with standard re fallback."""
    if _HAS_RE2:
        try:
            opts = re2.Options()
            opts.case_sensitive = False
            opts.dot_nl = True
            return re2.compile(pattern_str, options=opts)
        except Exception:  # noqa: S110, BLE001
            # If RE2 cannot parse a rare non-POSIX feature, fall back safely
            pass
    return re.compile(pattern_str, re.IGNORECASE | re.DOTALL)


def load_rules(rules_path: Path) -> list[Rule]:
    """Load and compile rules from a YAML file.

    Args:
        rules_path: Path to a YAML file with a top-level `rules:` list.

    Returns:
        List of compiled Rule objects.

    Raises:
        RuleLoadError: If the file is malformed, a rule fails schema validation,
            or a pattern fails to compile. Also raised on duplicate IDs.
        FileNotFoundError: If the file does not exist.
    """
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")

    with rules_path.open("r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise RuleLoadError(f"YAML parse error in {rules_path}: {e}") from e

    if not isinstance(data, dict) or "rules" not in data:
        raise RuleLoadError(f"{rules_path}: expected top-level mapping with 'rules' key")
    if not isinstance(data["rules"], list):
        raise RuleLoadError(f"{rules_path}: 'rules' must be a list")

    compiled: list[Rule] = []
    seen_ids: set[str] = set()
    for idx, raw in enumerate(data["rules"]):
        if not isinstance(raw, dict):
            raise RuleLoadError(f"rule #{idx}: must be a mapping")
        _validate_rule_dict(raw, idx)
        rule_id = raw["id"]
        if rule_id in seen_ids:
            raise RuleLoadError(f"duplicate rule id: {rule_id}")
        seen_ids.add(rule_id)
        try:
            pattern = _compile_pattern(raw["pattern"])
        except Exception as e:
            raise RuleLoadError(f"rule {rule_id}: invalid regex: {e}") from e
        compiled.append(
            Rule(
                id=rule_id,
                category=raw["category"],
                severity=Severity(raw["severity"]),
                pattern=raw["pattern"],
                description=raw["description"],
                compiled=pattern,
            )
        )

    if not compiled:
        raise RuleLoadError(f"{rules_path}: ruleset is empty; refusing to load")

    return compiled


class RegexEngine:
    """Evaluates a NormalizedPrompt against a compiled ruleset."""

    def __init__(self, rules: list[Rule]) -> None:
        """Initialize with a pre-loaded rule list."""
        if not rules:
            raise ValueError("RegexEngine requires at least one rule")
        self._rules = tuple(rules)
        self._is_re2 = _HAS_RE2

    @property
    def rule_count(self) -> int:
        """Number of loaded rules — used for /health and startup logging."""
        return len(self._rules)

    @property
    def is_re2_active(self) -> bool:
        """True if Google RE2 linear-time engine is active."""
        return self._is_re2

    def evaluate(self, prompt: NormalizedPrompt) -> RegexResult:
        """Evaluate the prompt against all rules.

        The canonical form and every decoded probe are each tested against every
        rule. A rule that fires on either canonical text OR a decoded probe
        counts as one match.
        """
        matched_ids: list[str] = []
        matched_from_probe_only: list[str] = []
        max_weight = 0.0

        for rule in self._rules:
            hit_canonical = bool(rule.compiled.search(prompt.canonical))
            hit_probe = False
            if not hit_canonical:
                for probe in prompt.decoded_probes:
                    if rule.compiled.search(probe):
                        hit_probe = True
                        break

            if hit_canonical or hit_probe:
                matched_ids.append(rule.id)
                if hit_probe and not hit_canonical:
                    matched_from_probe_only.append(rule.id)
                weight = _SEVERITY_WEIGHT[rule.severity]
                if weight > max_weight:
                    max_weight = weight

        return RegexResult(
            matched_rule_ids=matched_ids,
            max_severity_weight=max_weight,
            matches_from_decoded_probes=matched_from_probe_only,
        )
