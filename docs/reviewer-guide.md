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

Expected: eight hostile proposals, only `DENY` or `NULL`, zero execution through CERBERUS NULL. The synthetic naïve comparator executes registered hostile tools.

## 8–10 minutes: verify claim evidence

```bash
make test
make evidence
cerberus evidence inspect evidence/baseline-v0.1.0
```

Compare [assurance claim C1](assurance-case.md) with the architecture, property/adversarial tests, and `decisions.jsonl` / `execution.jsonl`. Read [limitations](limitations.md) before accepting the conditional claim.
