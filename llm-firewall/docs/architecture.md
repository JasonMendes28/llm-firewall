# Architecture

## High-level flow

```
Client ── HTTPS ──▶ Caddy (TLS termination) ── HTTP ──▶ Firewall
                                                          │
                                          ┌───────────────┼───────────────┐
                                          │               │               │
                                       AuthN        Rate limiting    Input validation
                                          │
                                          ▼
                                Detection pipeline
                                   1. Normalize (Unicode / evasion)
                                   2. Regex layer
                                   3. Classifier (best-effort)
                                   4. Fusion + mode gating
                                          │
                                          ▼
                                    Verdict
                                          │
                                    ┌─────┴─────┐
                                    │ allowed?  │
                                    └─────┬─────┘
                                    yes ──┤── no
                                          │
                                          ▼            ┌──────────────┐
                                    Forward to   ────▶ │  Claude API  │
                                    upstream           └──────────────┘

At every step:  audit event (hash-only by default) ──▶ stdout (JSON)
```

## Modules

| Module | Responsibility |
|--------|----------------|
| `firewall.config` | Env-driven Settings with prod-posture validation |
| `firewall.detection.normalizer` | Unicode NFKC, zero-width strip, homoglyph collapse, decoded probes |
| `firewall.detection.regex_engine` | YAML rules → compiled patterns → matches + severity |
| `firewall.detection.classifier` | DistilBERT wrapper with lazy load + graceful failure |
| `firewall.detection.fusion` | `max(regex, classifier) + capped evasion bonus` → action |
| `firewall.detection.pipeline` | Orchestrates the above and emits an immutable `Verdict` |
| `firewall.api.auth` | Argon2id API-key auth |
| `firewall.api.rate_limit` | In-memory token bucket + `RateLimiter` protocol for Redis later |
| `firewall.api.routes` | `/health`, `/v1/check`, `/v1/batch`, `/v1/proxy` |
| `firewall.audit.logger` | Hash-first structured JSON audit events |
| `firewall.proxy.claude_client` | Minimal async httpx client for Anthropic Messages |

## Data / control flow

**Every request** goes through: `auth → rate-limit → schema validation → size
validation → detection pipeline → audit → (proxy if `/v1/proxy`)`. There is
no bypass path. If any step fails, a typed `FirewallError` is raised and
mapped to a uniform JSON envelope by the exception handler in `main.py`.

**The detection pipeline is pure** — it takes a string, returns a `Verdict`,
and has no external side effects. All I/O (logging, upstream calls) happens
in the route layer. This makes the pipeline trivially unit-testable and gives
us a clean seam for `shadow` mode: the same verdict logic runs, only the
response action changes.

## Key design decisions

Rather than paraphrase them, the ADRs are the single source of truth:

- [ADR-001 — stdout JSON logs, no database in v1](adr/0001-stdout-json-no-database.md)
- [ADR-002 — fail degraded, not open or closed](adr/0002-fail-degraded-not-open-or-closed.md)
- [ADR-003 — hash-first audit logging](adr/0003-hash-first-logging.md)
- [ADR-004 — in-process classifier hosting](adr/0004-in-process-model.md)
- [ADR-005 — API-key auth over OAuth](adr/0005-api-key-auth.md)
- [ADR-006 — decode base64/hex for inspection only](adr/0006-decode-for-inspection-only.md)
- [ADR-007 — in-memory rate limiter, Redis-swappable](adr/0007-in-memory-rate-limit.md)
- [ADR-008 — TLS at the edge, not in the app](adr/0008-tls-at-edge.md)
- [ADR-009 — verdicts expose rule IDs only, no descriptions](adr/0009-verdict-omits-rule-descriptions.md)
- [ADR-010 — per-layer latency gated behind DEBUG_TIMING](adr/0010-debug-timing-gated.md)
- [ADR-011 — discrete severity tiers (low/medium/high)](adr/0011-discrete-severity-tiers.md)
- [ADR-012 — worst-of-both fusion + capped evasion bonus](adr/0012-fusion-worst-of-both.md)
