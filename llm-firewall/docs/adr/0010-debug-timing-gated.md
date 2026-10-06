# ADR-010: Per-layer latency in verdicts is gated behind DEBUG_TIMING

**Status:** Accepted

## Context

The verdict originally exposed a `latency` sub-object breaking down time
spent in normalize / regex / classifier / fusion. Useful for performance
tuning and load-test analysis.

It's also a subtle side channel. If `classifier_ms ≈ 0` and `regex_ms > 0`,
the attacker can infer that a regex rule fired, the pipeline short-circuited,
and the classifier never even ran. Or vice versa. Over many probes an attacker
learns which layer is doing the work on their inputs.

## Decision

- Per-layer latency is **collected** whenever `DEBUG_TIMING=true`.
- The API response **omits** the `latency` field entirely when `DEBUG_TIMING=false`.
- Prod config refuses to start with `DEBUG_TIMING=true` — this feature is
  intended for dev, tuning, and load-testing environments.

The dev `docker-compose.dev.yml` sets `DEBUG_TIMING=true`; the prod
`docker-compose.yml` explicitly sets it to `false` with a comment linking
to this ADR.

## Consequences

Positive:
- Useful engineering telemetry without giving it away to every caller.
- Load-testing captures the numbers we need for the writeup.
- Prod deployments can't accidentally leak the side channel because the
  config validator refuses.

Negative:
- Debugging a specific slow request in prod requires either an ephemeral
  DEBUG_TIMING enable, or scraping timings from server-side logs (which
  `AuditLogger` could be extended to emit).
