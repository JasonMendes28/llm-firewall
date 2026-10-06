# LLM Firewall

A high-performance, production-grade detection and security proxy that inspects prompts
and model responses for jailbreak / prompt-injection attempts, credential leaks, and system
prompt exfiltration before and after reaching an upstream LLM (Claude in this build).

```
┌────────────┐   HTTPS    ┌──────────────────────────────────────────────┐   HTTPS   ┌──────────────┐
│   Client   │ ─────────► │                 LLM Firewall                 │ ────────► │  Claude API  │
│ (app/user) │            │  async auth → validate → normalize →         │           └──────────────┘
│            │ ◄───────── │  RE2 regex → classifier → fusion → verdict   │ ◄─────────
└────────────┘            │  proxy: SSE streaming + egress guardrail     │
                          └──────────────────────────────────────────────┘
```

## Production Engineering Highlights

- **ReDoS-Immune Pattern Matching**: Powered by **Google RE2** (`google-re2`), guaranteeing
  strict $O(N)$ linear-time evaluation with zero catastrophic backtracking under adversarial payloads.
- **Non-Blocking Auth with TTL Caching**: High-entropy API tokens are verified via Argon2id
  in a dedicated thread pool and cached in a thread-safe in-memory TTL cache (5-minute window).
  Valid requests authenticate in sub-microsecond time without blocking Python's asyncio event loop.
- **Striped & Bounded Rate Limiting**: Features a 32-shard mutex design to eliminate lock
  contention across concurrent threads, paired with active TTL and LRU eviction to prevent
  memory leak DoS vulnerabilities.
- **Prometheus Telemetry & Observability**: First-class Prometheus `/metrics` endpoint exposing
  Google SRE Golden Signals: request rates, request duration histograms, pipeline stage latencies
  (`normalize`, `regex`, `classifier`, `fusion`), risk score distribution, rule match counters,
  and rate-limiting / egress block metrics.
- **Streaming Proxy & Egress Guardrail**: Full support for real-time Server-Sent Events (SSE)
  via `stream: true`, alongside active egress scanning that inspects model responses for
  system prompt exfiltration, canary tokens, and credential leaks (AWS keys, private keys, API tokens).
- **Graceful ML Degradation**: DistilBERT classifier predictions run off-thread via `asyncio.to_thread`.
  If the ML layer is unavailable, the service degrades gracefully to regex-only evaluation with
  a clear `degraded: true` flag.

## Current Corpus Metrics (RE2 Path)

Measured against `tests/redteam/corpus/`:

| Split               | n  | Precision | Recall | F1     | FPR  |
|---------------------|----|-----------|--------|--------|------|
| Direct attacks      | 20 | 1.00      | 1.00   | 1.00   | 0.00 |
| Obfuscated attacks  | 13 | 1.00      | 1.00   | 1.00   | 0.00 |
| Multi-turn attacks  |  5 | 1.00      | 0.20   | 0.33   | 0.00 |
| Benign look-alikes  | 24 | —         | —      | —      | 0/24 |
| **Overall**         | 62 | **1.00**  | **0.895** | **0.944** | **0.0** |

Latency, regex-only path: **p50 = 0.05 ms, p95 = 0.14 ms, p99 = 0.17 ms**.

## Endpoints

| Method | Path         | Auth | Purpose |
|--------|--------------|------|---------|
| GET    | `/health`    | no   | Liveness / readiness (reports `degraded` and `re2_active`) |
| GET    | `/metrics`   | no   | Prometheus metrics exposition endpoint |
| POST   | `/v1/check`  | yes  | Evaluate a prompt without forwarding |
| POST   | `/v1/batch`  | yes  | Evaluate up to 256 prompts (offline red-team runs) |
| POST   | `/v1/proxy`  | yes  | Evaluate then forward to Claude (buffered or SSE streaming) with egress guardrail |

OpenAPI docs auto-served at `/docs` when running.

### Verdict Shape

```json
{
  "request_id": "8f86f773-...",
  "allowed": false,
  "action_taken": "block",
  "risk_score": 0.9,
  "classifier_confidence": 0.05,
  "matched_rule_ids": ["R-OVERRIDE-001"],
  "mode": "hard_block",
  "degraded": false,
  "prompt_hash": "sha256:...",
  "prompt_length": 64,
  "timestamp": "2026-10-06T..."
}
```

Rule IDs only — rule descriptions are **deliberately** withheld from responses so
attackers cannot fuzz the ruleset with an oracle. See
[ADR-009](docs/adr/0009-verdict-omits-rule-descriptions.md).

### Proxy Request Shape (Streaming & Buffered)

```json
{
  "prompt": "Explain photosynthesis in simple terms",
  "model": "claude-3-5-sonnet-latest",
  "max_tokens": 1024,
  "stream": false
}
```

When `stream: true`, the firewall proxies real-time Server-Sent Events (`text/event-stream`)
directly from Claude after the prompt verdict is confirmed safe.

## Setup

### Local Dev

```bash
cp .env.example .env
pip install -r requirements-dev.txt
make test           # unit + integration (120+ tests)
make test-redteam   # red-team SLO suite
make run            # uvicorn on :8080 with --reload
```

### Docker (Production-Shaped)

```bash
# Dev — HTTP on :8080
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# Prod-shaped — HTTPS via Caddy with non-root security container:
docker compose up -d
```

### Generate an API Key

```bash
python -m firewall.api.auth hash <your-plaintext-key>
# Copy output into FIREWALL_API_KEYS_HASHED in .env
# (newline- or `;;`-separated for multiple keys)
```

## Configuration Tuning

Every threshold is env-driven; no hardcoded magic numbers exist in the detection code.

| Variable | Default | Effect |
|----------|---------|--------|
| `BLOCK_THRESHOLD` | 0.80 | risk_score ≥ this → block |
| `WARN_THRESHOLD`  | 0.50 | risk_score ≥ this → warn |
| `BLOCKING_MODE`   | `hard_block` | `hard_block` / `soft_warn` / `shadow` |
| `RATE_LIMIT_RPS`  | 20 | sustained requests / second per key |
| `RATE_LIMIT_BURST`| 40 | burst capacity |
| `MAX_PROMPT_CHARS`| 16384 | rejected earlier than detection pipeline |
| `DEBUG_TIMING`    | false | per-layer latency in verdict (dev only) |
| `LOG_FULL_PROMPTS`| false | opt-in plaintext audit; only for warn/block |

Adding regex rules: edit `rules/default_rules.yaml`. The engine compiles and validates
the file at startup and refuses to load a malformed ruleset.

## Security & Reliability Posture

- **Linear-Time RE2 Evaluation**: Eliminates catastrophic backtracking / ReDoS.
- **Asynchronous Auth with TTL Verification Cache**: Sub-microsecond validation on verified tokens; off-thread Argon2 hashing.
- **Egress Guardrails**: Scans upstream responses for leaked system prompts, canary tokens, and credentials.
- **Argon2id Salted Hashes**: Raw client secrets are never stored or logged.
- **Hash-First Audit Logging**: Prompts are hashed with SHA-256 in logs by default ([ADR-003](docs/adr/0003-hash-first-logging.md)).
- **Graceful ML Degradation**: Service remains online and blocks attacks even if PyTorch/DistilBERT fails ([ADR-002](docs/adr/0002-fail-degraded-not-open-or-closed.md)).
- **Container Hardening**: Non-root user (uid 10001), read-only root filesystem, `cap_drop: ALL`, `no-new-privileges: true`.

## Documentation

- [Architecture](docs/architecture.md)
- [Architecture Decision Records](docs/adr/)
- [Red-team report](docs/redteam_report.md)
- [Known limitations and future work](docs/limitations.md)
- [Tuning guide](docs/tuning.md)

## License

MIT.
