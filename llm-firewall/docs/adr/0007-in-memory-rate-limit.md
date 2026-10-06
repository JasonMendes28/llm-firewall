# ADR-007: In-memory token bucket; Redis-swappable via a Protocol

**Status:** Accepted

## Context

Rate limiting protects the classifier's inference budget and defends against
brute-force probing of the ruleset.

Two backends were considered:

1. In-memory token bucket — process-local, no dependencies.
2. Redis-backed distributed token bucket — accurate across many instances.

## Decision

Ship the in-memory bucket in v1, behind a `RateLimiter` Protocol so a Redis
implementation can be added without touching the call site.

## Consequences

Positive:
- Zero-dependency deployment. `docker-compose` doesn't need Redis to run.
- Fast path (no network round trip on the hot path).
- Sufficient for single-instance deployments and small-team demos.

Negative:
- **Multi-instance deployments are inaccurate.** N instances each enforce
  the configured RPS independently, so effective total is N × RPS. Called
  out explicitly in the README.
- Bucket state is lost across restarts. Not a real issue for a stateless
  service.

## Future work

Redis implementation is a straightforward addition: same `RateLimiter`
interface, `INCR`/`EXPIRE`-based algorithm. Would come with its own ADR
covering fail-mode (what if Redis is down — probably: log and fall back to
in-memory local, rather than fail-closed on rate limiting).
