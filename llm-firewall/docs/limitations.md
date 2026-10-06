# Known Limitations and Future Work

Being explicit about what this system does **not** do is part of the
security posture. If a limitation isn't listed here, it's either not known
or an oversight — please open an issue.

## Detection scope

**Multi-turn attacks are the primary weakness.** The current regex-only path
catches 1/5 multi-turn attacks in the corpus. The pipeline sees only the
current request; a multi-turn attack that unfolds across five turns has four
turns of benign-looking setup we can't distinguish from legitimate role-play.

*Mitigation path:* the DistilBERT classifier is the right layer for this;
regex fundamentally cannot handle it. See red-team report §"multi-turn
misses" for the concrete plan.

**Adversarial-suffix attacks** (Zou et al. 2023, "Universal and Transferable
Adversarial Attacks on Aligned Language Models") are not covered. These
gradient-optimized suffixes look like random tokens and are designed to trip
the *target model's* safety training. Detecting them requires either the
target model's gradients or a classifier trained specifically on them.

**Cross-lingual attacks.** Rules are English-language. A payload translated
into a low-resource language, especially with a request to translate the
response, will not be caught by the regex layer. A multilingual DistilBERT
base would help; the current one is English-only.

**Prompt smuggling via structured content.** Attacks embedded in Markdown
link titles, YAML front-matter, JSON string values re-parsed downstream, etc.
Bounded decoding covers base64/hex but not arbitrary structured formats.

**Model-specific chat-template attacks.** The firewall sees the prompt as
opaque text; it doesn't know about the upstream's chat template. A
`<|end_of_turn|>` injection targeted at a specific tokenizer will pass through.

## Deployment scope

**In-memory rate limiting is per-process.** Multi-instance deployments have
effective RPS = N × configured RPS
([ADR-007](adr/0007-in-memory-rate-limit.md)). A Redis backend swap-in is
designed for.

**No persistent audit store in v1.** JSON logs to stdout only; long-term
retention is the log aggregator's responsibility
([ADR-001](adr/0001-stdout-json-no-database.md)).

**No user-facing identity model.** All API keys have identical authority;
no per-user quota, no revocation without redeploy
([ADR-005](adr/0005-api-key-auth.md)).

**Single upstream.** The proxy currently supports one Claude model per
request; it doesn't route between multiple upstream providers.

## Classifier scope

**No trained model shipped.** `models/train.py` is reproducible but the
artifact is not committed. Numbers in the red-team report are for the
**regex-only** path. When a trained classifier is loaded, expect:

- Higher recall on multi-turn and semantically-novel attacks.
- Slightly higher latency (5–20 ms depending on hardware and truncation).
- Slightly higher false-positive rate on benign look-alikes (needs calibration).

**No calibration guarantee.** DistilBERT probabilities are not calibrated
out of the box. `models/evaluate.py` reports raw metrics; a production
deployment should also compute a reliability diagram and consider Platt
scaling / isotonic regression on top.

## Operational scope

**No secrets manager integration.** API keys and the Claude key are loaded
from env vars — the right shape for Kubernetes Secrets, AWS Secrets Manager,
Vault — but the integration is on the operator.

**No graceful shutdown for in-flight requests.** FastAPI/Uvicorn defaults
are used; a SIGTERM will let in-flight requests finish within the default
grace window.

**No canary / A-B evaluation of rule changes.** Shadow mode is the closest
thing — deploy a new ruleset in `shadow` mode, compare verdicts against
production, promote once satisfied.

## Testing scope

**Corpus size.** The shipped corpus is 62 prompts. Enough to prove the
pipeline works end-to-end, too small to serve as a rigorous benchmark. Real
deployment should validate against JailbreakBench / HarmBench held-out
splits, and against the deployment's own traffic distribution once in
`shadow` mode.

**No fuzzing.** The regex compiler and YAML loader are covered by unit
tests but not systematically fuzzed. A `hypothesis`-based property test
suite is a v2 candidate.

**No red-team-vs-red-team.** The corpus is human-written. A more rigorous
future round would use an LLM-in-the-loop attacker generating adversarial
variants against the current ruleset.

## v2 roadmap (ordered by impact)

1. **Fine-tune DistilBERT** on multi-turn corpora; ship weights + artifact hash.
2. **Framing detector** for role-play + payload structural patterns.
3. **Redis rate limiter** for multi-instance correctness.
4. **Persistent audit store** with parameterized queries and its own ADR.
5. **Calibration layer** on classifier output.
6. **Multilingual regex ruleset** for the top 5 non-English attack surfaces.
7. **Property-based fuzzing** of the normalizer and rule loader.
