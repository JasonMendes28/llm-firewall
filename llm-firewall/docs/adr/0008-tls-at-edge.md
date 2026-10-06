# ADR-008: TLS terminated at the edge, not in the app; prod refuses to start without explicit acknowledgement

**Status:** Accepted

## Context

The firewall handles inbound traffic from clients over the internet. HTTPS is
non-negotiable. The question is where to terminate it.

## Decision

TLS is terminated at a reverse proxy in front of the firewall (Caddy in the
shipped `docker-compose.yml`). The firewall itself listens plain HTTP inside
the container network.

To prevent someone forgetting the reverse proxy, `FIREWALL_ENV=prod` refuses
to start unless `TRUST_PROXY=true` is set. That env var is a semantic
statement — *"I have deployed a TLS-terminating reverse proxy in front of
this service"*.

## Consequences

Positive:
- App code doesn't handle TLS. Cert rotation, cipher suite selection, and
  protocol upgrades are the reverse proxy's job. Caddy handles Let's Encrypt
  automatically.
- Industry-standard pattern; matches how nearly every production Python web
  service is deployed.
- The explicit `TRUST_PROXY` acknowledgement makes it structurally hard to
  accidentally deploy the firewall on plaintext.

Negative:
- Local development runs on HTTP. Dev-compose reflects this.
- One more piece of infrastructure to configure (Caddyfile).

## Related

- Caddyfile ships in `deploy/Caddyfile` with HSTS, no-referrer, X-Frame-Options
  DENY, and other JSON-API-appropriate security headers.
