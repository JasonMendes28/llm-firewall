# ADR-002: When the ML classifier is unavailable, degrade — don't fail open or closed

**Status:** Accepted

## Context

The DistilBERT classifier can fail to load (bad artifact, hash mismatch, OOM)
or fail to serve (transient inference error). The service must decide what to
do with incoming requests in that state.

The three obvious options:

1. **Fail open** — allow everything through, log a warning.
2. **Fail closed** — block everything, log a warning.
3. **Degrade** — run the regex layer only, mark the verdict `degraded: true`,
   log the reason at WARNING level.

## Decision

Option 3.

- If `classifier.load()` raises at startup, the service still starts. Logs a
  loud `classifier_load_failed_starting_in_degraded_mode` event.
- If `classifier.predict()` raises at request time, we set a **sticky**
  degradation flag on the classifier so `/health` reports `degraded: true`
  from then on. Requests continue to be served regex-only.
- The `degraded` boolean is present on every verdict; `classifier_confidence`
  is `null` in degraded mode so callers can't misinterpret it as a low score.

## Consequences

Positive:
- A partial outage is still partial. Regex catches the highest-signal attacks
  (100% recall on our direct-attack corpus) even without the classifier.
- Ops sees `degraded=true` on `/health` immediately, without waiting for a
  correlated dashboard signal.
- No pressure to disable the firewall entirely when the model service is flaky,
  which is what tends to happen with a fail-closed design.

Negative:
- A determined attacker who can knock out the classifier gets a weaker
  detection surface. Mitigation: the classifier is in-process (ADR-004), so
  taking it down means taking the firewall down, at which point traffic
  bypasses the whole thing anyway (there is no separate failure of the ML
  component that would leak past a healthy firewall).

## Sticky vs. transient failure

We chose sticky degradation (once a `predict()` call fails, we stay degraded
until restart) over transient (retry each request) because flapping backends
produce inconsistent verdicts, which is worse than consistently reduced
protection.
