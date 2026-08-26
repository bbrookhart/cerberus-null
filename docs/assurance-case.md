# Assurance case

## Claim C1 — prohibited autonomous actions do not reach a protected adapter

**Argument.** Every registered adapter requires the gateway's private permit; the gateway executes only `ALLOW`; T4, unknown, malformed, unresolved, and stopped requests resolve to non-executable outcomes.

**Evidence.** Architecture tests in `tests/architecture/test_boundary.py`; property test `test_inv_ot_prohibited_actions_never_execute`; EVAL-002, EVAL-009, EVAL-010, and EVAL-012; baseline `decisions.jsonl` and `execution.jsonl`.

**Assumptions.** Host/process isolation and trusted code remain intact; the registry and policy have not been administratively replaced.

## Claim C2 — the planner cannot grant itself authority

**Argument.** The broker accepts only known issuer-created grants whose canonical payload matches the signed, stored artifact. Capabilities are non-delegable, scoped, expiring, revocable, and use-limited.

**Evidence.** Capability unit tests; EVAL-003 and EVAL-008; property test for out-of-scope resources.

**Assumptions.** The HMAC key remains unavailable to the untrusted layer.

## Claim C3 — human approval is bound to one exact request

**Argument.** Approval signs the request binding, including request, mission, action, resource, controller, and parameter hash; approval is expiring and single-use.

**Evidence.** Approval unit tests and EVAL-007.

**Assumptions.** The operator identity and approval issuer are authentic.

## Claim C4 — emergency stop preserves human sovereignty

**Argument.** An engaged stop returns `NULL` for every action above T0. Only an active human identity can release it.

**Evidence.** Emergency-stop unit/property tests and EVAL-009.

## Conditional top-level claim

Under the v0.1 threat model, code and policy configuration, deterministic synthetic agents, and EVAL-001–EVAL-012, the committed baseline observed no prohibited action crossing the CERBERUS NULL execution boundary. This is bounded empirical evidence, not a universal safety proof.
