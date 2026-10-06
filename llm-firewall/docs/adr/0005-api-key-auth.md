# ADR-005: API-key authentication (Argon2id) instead of OAuth

**Status:** Accepted

## Context

The firewall's own API needs authentication. The two mainstream choices are:

1. OAuth2 (bearer JWTs, refresh flows, an identity provider).
2. Static API keys hashed at rest.

## Decision

Static API keys, hashed with Argon2id. Presented via
`Authorization: Bearer <key>`. Verification uses argon2's built-in verify.

Delimiter for the config env var is **newline or `;;`**, deliberately not
comma — Argon2 encoded hashes contain commas internally (`m=65536,t=3,p=4`)
and a comma delimiter would silently split them.

## Consequences

Positive:
- Matches the ecosystem norm for service-to-service API auth (Anthropic,
  OpenAI, Stripe all use static keys).
- No identity provider dependency, no token refresh flow, no JWKS rotation.
- Keys are hashed at rest with a modern KDF; the plaintext key is never stored.
- CLI helper (`python -m firewall.api.auth hash`) makes key issuance a
  one-liner for operators.

Negative:
- No per-user identity or fine-grained scoping. All keys have identical
  authority.
- Key rotation is manual (edit the env var, restart). No revocation without a
  redeploy.

## Future work

For deployments with human users (as opposed to backend services), OAuth2 is
the right answer and the `_authenticate` function in `routes.py` is small
enough to swap out.
