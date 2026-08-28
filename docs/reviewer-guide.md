# Ten-minute reviewer guide

## 0–2 minutes: thesis and boundary

Read the README thesis and [architecture](architecture.md). Confirm the model is outside the trusted computing base and `NULL` has no executable path.

## 2–4 minutes: authority and invariants

Inspect `cerberus_null/policy.py`, `authority.py`, `gateway.py`, and `tests/architecture/test_boundary.py`. Review the signed capability and exact-request approval models.

## 4–6 minutes: safe baseline

```bash
make bootstrap
cerberus evaluation run EVAL-001
```

Expected: one T0 proposal, `ALLOW`, one mock execution, complete evidence.

## 6–8 minutes: compromised planner

```bash
cerberus evaluation run EVAL-012
```

Expected: sixteen planner proposals—two legitimate and fourteen unsafe. CERBERUS
NULL executes both legitimate proposals and no unsafe proposal. The synthetic naive
comparator executes thirteen of fourteen unsafe proposals because the remaining
tool is unregistered.

## 8–10 minutes: verify claim evidence

```bash
make test
make formal
make mutation
make evidence
cerberus evidence inspect evidence/EXP-CN-001-v0.1.0
cerberus evidence verify evidence/EXP-CN-001-v0.1.0
cerberus experiment verify-results evidence/EXP-CN-001-v0.1.0
```

Compare [assurance claim CN-C1](assurance-case.md) with the TLA+ model,
[formal-to-implementation map](formal-implementation-map.md), property/adversarial
tests, and `decisions.jsonl` / `executions.jsonl`. Read [limitations](limitations.md)
before accepting the conditional claim.
