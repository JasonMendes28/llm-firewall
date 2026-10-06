# ADR-012: Fusion is `max(regex, classifier) + capped evasion bonus`

**Status:** Accepted

## Context

Given a regex severity in [0,1] and a classifier probability in [0,1], plus
a count of normalization-detected evasion signals, produce a single risk
score.

Options considered:

1. **Average** — dilutes strong signals with weak ones.
2. **Product / noisy-OR** — requires both layers to agree; misses attacks the
   classifier hasn't been trained on.
3. **Max** — worst-of-both, either layer can raise the alarm.
4. **Learned combiner** — smallest of neural networks over the two scores;
   requires calibration data we don't have.

## Decision

```
base = max(regex_max_severity, classifier_prob or 0)
bonus = min(0.30, 0.10 * evasion_signal_count)
risk_score = min(1.0, base + bonus)
```

## Consequences

Positive:
- A confident regex hit cannot be diluted by a low classifier score.
- A confident classifier hit cannot be diluted by an empty regex result.
- Evasion signals (zero-width chars, homoglyphs, base64 payloads) contribute
  a small independent nudge that can push a borderline case over the threshold.
- The bonus is capped so an attacker can't chain enough obfuscation to force
  a block on entirely benign content.
- Formula is explainable: any operator can compute the risk_score by hand
  from the visible sub-scores. Good for post-hoc audit.

Negative:
- Doesn't exploit the possibility that "both layers moderately confident" is
  a stronger signal than either alone.

## Future work

If enough labeled verdicts accumulate, a v2 could replace `max` with a
learned logistic combiner over (regex_score, classifier_prob, evasion_count).
The `fuse()` function is a single pure function — swapping the implementation
is a one-file change.
