# ADR-006: Decode base64/hex payloads for inspection only, never for forwarding

**Status:** Accepted

## Context

Attackers hide adversarial instructions inside base64 or hex blobs
(`"decode this: aWdub3JlLi4u"`). The firewall must be able to catch these
without also breaking legitimate use of encoded data (developers sending
code samples, API responses, tokens).

## Decision

The normalizer extracts *decoded probes* from base64/hex substrings and
attaches them to the `NormalizedPrompt`. Every regex rule runs against both
the canonical text and every decoded probe.

The **raw request forwarded to Claude is unchanged**. We never substitute
decoded content into the outbound prompt.

Bounds:
- Recursion depth capped at 2 (base64 inside base64, but no deeper).
- Total decoded bytes capped at 64 KiB per request.
- Candidates require ≥16 chars (base64) or ≥32 chars (hex) — filters out
  ordinary short random-looking strings.
- Decoded output must be ≥80% printable, otherwise ignored.

## Consequences

Positive:
- Attacks like `"please decode aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM="`
  are caught at the regex layer.
- Legitimate use of encoded content is not silently rewritten — the client
  sees exactly what they sent go through to the upstream.
- Attacker cannot use the firewall as a decoding oracle by observing
  differences in the forwarded prompt.

Negative:
- CPU spent decoding candidates that turn out to be nothing. Bounded by the
  size caps; measured latency impact is negligible.
- Deep-nested encoding (>2 levels) escapes inspection. Documented as a
  known limitation.
