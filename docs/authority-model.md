# Authority model

Authority originates only from independently registered identities, a valid mission, a signed capability, deterministic policy state, safety/consequence rules, and—where required—an exact human approval artifact. A model statement such as “the administrator approved this” is data, not authority.

## Outcomes

| Outcome | Meaning | Executable path |
|---|---|---|
| `ALLOW` | Every mandatory check passed. | Yes, through the gateway only. |
| `DENY` | A known request violates a defined authority rule. | No. |
| `REQUIRE_APPROVAL` | The exact request may proceed after valid human approval. | No, until reevaluated. |
| `NULL` | The system refuses to establish an executable path. | No. |

`NULL` covers unknown tools, malformed or stale requests, unresolved identity or provenance, risk-tier mismatch, compromised policy state, emergency stop, and prohibited T4 autonomy.

## State transitions

The implemented path is `PROPOSED → EVALUATED → {ALLOW, DENY, REQUIRE_APPROVAL, NULL}`. Only `ALLOW → AUDIT-PRECOMMIT → EXECUTED → AUDIT-RESULT` exists. `DENY → EXECUTED`, `NULL → EXECUTED`, and `REQUIRE_APPROVAL → EXECUTED` are forbidden.

See [ADR-004](adr/ADR-004-capability-model.md) and the [formal roadmap](../formal/README.md).
