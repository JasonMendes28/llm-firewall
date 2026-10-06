# ADR-003: Hash-first audit logging; full plaintext is opt-in

**Status:** Accepted

## Context

Audit logs for a security service tempt operators toward logging everything.
For this service, "everything" includes user prompts that may contain:

- Personal data the user pasted in.
- Secrets or credentials leaked into a prompt by a misconfigured app.
- Adversarial payloads — which are, by definition, content we've decided is
  dangerous. Storing them at scale creates a compact attack corpus that would
  be extremely valuable to anyone who breaches the log store.

## Decision

Default posture:

- Every verdict emits one structured log line.
- Fields include SHA-256 of the raw prompt, its length, verdict fields
  (score, action, matched rule IDs), and the request ID.
- The **raw prompt is not logged**.

Opt-in via `LOG_FULL_PROMPTS=true`:

- Even when enabled, only prompts with `action_taken` of `warn` or `block`
  are logged in plaintext. Clean traffic remains hash-only.
- Documented as intended for controlled envs (research, tuning) with a
  retention TTL set at the log-store layer.
- Prod configuration refuses to start with `LOG_FULL_PROMPTS=true` unless
  explicitly overridden, so we don't silently turn it on.

## Consequences

Positive:
- Correlation across identical prompts still works — the hash is stable.
- Breach of the log store yields only hashes for the vast majority of traffic.
- Complies with a wide range of privacy regimes without needing per-tenant
  toggles.

Negative:
- Forensic investigation of an unusual verdict requires either (a) enabling
  full-prompt logging temporarily, or (b) having the client's own logs to
  correlate against the hash.
- Attackers can dedupe repeated attacks via the hash, but we do too, and the
  hash never leaves the audit log.
