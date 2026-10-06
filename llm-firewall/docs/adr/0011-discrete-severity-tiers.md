# ADR-011: Discrete severity tiers (low / medium / high), not continuous weights

**Status:** Accepted

## Context

Every regex rule contributes a weight to `risk_score`. The design options
were:

1. Continuous weights per rule (e.g. `severity: 0.72`).
2. Discrete tiers.

## Decision

Three discrete tiers, mapped to fixed weights:

| Tier   | Weight |
|--------|--------|
| low    | 0.3    |
| medium | 0.6    |
| high   | 0.9    |

## Consequences

Positive:
- Auditing a rule change is trivial. "This rule was medium, now high" is a
  reviewable statement; "this rule went from 0.63 to 0.71" is not.
- Prevents the anti-pattern of nudging a weight up by 0.05 to fix one false
  negative and shipping a subtle systemic bias.
- Discourages fake precision. Assigning "0.72" implies a calibration that
  regex rules don't have.

Negative:
- Loses expressiveness. Some rules are genuinely 70% confident and no tier
  captures that.
- Coarser downstream signal for the fusion layer.

## Mitigation

The classifier layer provides continuous [0,1] confidence — that's where fine
gradations live. Regex is the coarse-but-fast layer by design.
