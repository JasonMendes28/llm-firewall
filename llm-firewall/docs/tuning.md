# Tuning Guide

Everything user-tunable is env-driven — no code changes needed for any of
the operations below.

## Adjusting thresholds

Two knobs:

- `BLOCK_THRESHOLD` — `risk_score >= this` produces a block in hard-block mode.
- `WARN_THRESHOLD` — `risk_score >= this and < BLOCK_THRESHOLD` produces a warn.

Constraint: `WARN_THRESHOLD < BLOCK_THRESHOLD`. The service refuses to start
if violated.

**Raise `BLOCK_THRESHOLD`** when the corpus shows too many false positives on
your traffic. Recall drops, FPR improves.

**Lower `BLOCK_THRESHOLD`** when attacks are slipping through that fired a
mid-severity rule (score ≈ 0.6). Recall improves, FPR degrades.

**Preferred workflow:**

1. Deploy in `shadow` mode. Verdicts computed, nothing blocked.
2. Sample production traffic, categorize the misses and false positives.
3. Adjust the threshold (or add a rule / retune severity) based on the data.
4. Promote to `soft_warn`, then to `hard_block`.

## Adding a regex rule

Edit `rules/default_rules.yaml`:

```yaml
- id: R-NEWCATEGORY-001         # never reuse an ID
  category: newcategory          # free-form label
  severity: high                 # low / medium / high
  pattern: '\byour regex here\b' # tested with re.IGNORECASE | re.DOTALL
  description: >
    What this catches, and one example. This field is internal only —
    it is never returned in an API response.
```

Restart the service. The engine validates the ruleset at startup — a
malformed rule prevents startup rather than being silently skipped.

## Adding an evasion signal

If you find a new evasion class not covered by
`firewall.detection.normalizer.normalize()`, add it there. Signals are
returned in `NormalizedPrompt.evasion_signals` and each contributes `0.10`
to the fusion bonus (capped at `0.30`).

## Retraining the classifier

See `models/README.md`. Workflow:

1. Curate a JSONL dataset with `{text, label}` per line.
2. `python models/train.py --data data.jsonl --output models/artifact`.
3. Note the SHA-256 the script prints.
4. Set `CLASSIFIER_MODEL_SHA256=<hash>` in `.env` to pin the artifact.
5. Restart the firewall.

The pin means an attacker with write access to the model directory can't
swap in a more permissive model without also updating the config.

## Turning on plaintext audit logging

Only in a controlled environment with a retention policy at the log store.

```
LOG_FULL_PROMPTS=true
LOG_FULL_PROMPT_TTL_DAYS=7
```

Even with this on, only `warn` / `block` verdicts get plaintext. Clean
traffic stays hash-only. Prod refuses to start with `LOG_FULL_PROMPTS=true` —
this is intentional.

## Rate-limit tuning

- `RATE_LIMIT_RPS` — sustained tokens/second per API key.
- `RATE_LIMIT_BURST` — max tokens available in a burst.

Bucket keyed by SHA-256 prefix of the presented API key. Plaintext key
never touches the rate-limit map.

**Multi-instance deployments:** in-memory bucket is per-process. With N
replicas, effective limit is N × configured. Configure conservatively
(divide by N) or swap in the Redis-backed limiter when it lands.

## Blocking-mode rollout

Recommended progression when integrating in front of a live app:

1. **`shadow`** — deploy for 1–7 days. Grep audit logs for verdicts. Fix
   rules until FPR on your traffic is acceptable.
2. **`soft_warn`** — same detection, warnings only, real traffic still
   flows. Instrument your app to log incoming warn verdicts.
3. **`hard_block`** — enforce.

Switching mode is an env-var change and a restart. No code deploy required.
