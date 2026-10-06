# ADR-009: Verdicts expose rule IDs only, never descriptions

**Status:** Accepted

## Context

Every regex rule has an internal `description` explaining what it catches
(e.g. "Cyrillic/Greek homoglyph variant of 'ignore previous instructions'").
The initial schema draft returned these in the API response.

A verdict response of

```json
{"matched_rule_ids": [{"id": "R-EXFIL-002", "description": "asks for system prompt"}]}
```

tells an attacker exactly what the firewall is looking for. They can iterate:
tweak the prompt until the description changes, learn the ruleset, then
craft an evasion.

## Decision

Verdict responses contain **rule IDs only**:

```json
"matched_rule_ids": ["R-EXFIL-002"]
```

The `description` field exists on the internal `Rule` dataclass, is used in
audit logs and internal dashboards, but is **never** serialized to a client.
An integration test enforces this (grep the response body for the string
`description` — must not appear).

## Consequences

Positive:
- Attackers get a coarse signal (something was matched) but no oracle for
  which specific detection logic fired.
- Operators still have full detail — the audit log has the descriptions
  because it's internal.
- The response is smaller.

Negative:
- Legitimate integrators who want to display a helpful error to end users
  now need a client-side lookup table. Documented; the rule IDs are stable.
- Publishing the `default_rules.yaml` file publicly leaks the mapping. This
  is called out in the file's header — operators who fork should rotate rule
  IDs before public exposure.
