# ADR-001: Structured JSON logs to stdout, no database in v1

**Status:** Accepted

## Context

Audit trails for a security service need to be durable and queryable. The
options considered were:

1. Local SQLite for append-only audit rows.
2. A managed Postgres instance behind a parameterized-query DAL.
3. Structured JSON logs to stdout, aggregation is the operator's problem.

## Decision

Option 3. Every verdict produces exactly one JSON log line on stdout via
`structlog`. No database, no ORM, no migrations, no connection pool.

## Consequences

Positive:
- **Stateless service.** Restarts don't need warm-up, scale-out doesn't need a
  shared connection pool, no failure mode where "the DB is down" cascades into
  a hard question about fail-open vs fail-closed for the whole firewall.
- **Zero query surface.** No SQL/NoSQL injection to defend against; ADR-safe
  by construction. This directly satisfies the "no injection surface if a
  database is used" requirement — we don't use one, so there's nothing to defend.
- **Fits the ecosystem.** Real deployments already have log aggregators (Loki,
  ELK, Datadog). Adding a DB duplicates a solved problem.

Negative:
- Correlating events across a long time window requires the log store to be
  set up correctly. Documented in the deployment runbook.
- Local debugging of "what did this key do last week" requires `grep` on the
  log stream rather than a SQL query.

## Future work

Persistent storage for regulated deployments (PCI, HIPAA) is out of scope for
v1 but designed for: the `AuditLogger` interface is narrow and could gain a
second implementation without touching the pipeline. A v2 ADR would cover the
parameterized-query DAL and its own fail-mode analysis.
