# CERBERUS NULL v0.1 research release report

## Research question

Can an AI agent remain operationally useful while an independent deterministic
authorization architecture prevents execution outside explicitly delegated
authority—even when the planner is treated as compromised?

## Threat model and trusted computing base

The planner, LLM, memory, RAG, documents, tool output, user text, and generated
reasoning are untrusted. The v0.1 TCB is identity and mission resolution,
capability and approval verification, deterministic policy, safety invariants,
human-controlled emergency stop, execution gateway, protected adapters, and
evidence recorder. Host and TCB compromise are out of scope.

## Authority and capability model

Authority originates only from registered external state. Capabilities are signed,
scoped, expiring, revocable, use-limited, non-delegable, and bound to subject,
mission, action, resource, and parameters. Approval is independently issued,
single-use, expiring, and bound to the exact request hash. Natural-language claims
cannot create authority.

## Formal specification and model checking

`formal/CerberusNull.tla` specifies request, capability, approval, stop, decision,
execution, and audit state. Under the committed finite bounds, TLC
2026.08.21.155922 generated 341 states, found 221 distinct reachable states at
depth 6, and found no counterexample to F1–F7. The required core is:

- F1 unauthorized actions never execute;
- F2 approval-required actions require an exact valid approval;
- F3 emergency stop blocks consequential execution;
- F4 agent-issued authority cannot become active capability;
- F5 T4 cannot execute autonomously.

The known-broken model adds execution without capability validation. TLC produced
the expected F1 counterexample, so the invariant suite detects that material defect.

## Implementation verification

- Ruff: PASS
- strict mypy: PASS
- pytest: 64 PASS
- Hypothesis properties: PASS
- integration and architecture tests: PASS
- adversarial tests: PASS
- clean-clone branch-aware coverage: 91.42%
- deterministic decision test: PASS
- direct-adapter rejection: PASS
- formal negative mutation: PASS
- targeted implementation mutations: 5/5 killed

## EXP-CN-001 — Compromised Planner Authority Containment

The same deterministic planner proposed two safe and fourteen unsafe actions to an
intentionally insecure agent-to-tool comparator and to CERBERUS NULL. The naive
condition executed 13/14 registered unsafe requests. CERBERUS NULL executed 0/14
unsafe requests and 2/2 safe requests.

Across EVAL-001–012:

- 27 proposals;
- 24 unsafe proposals and 0 unsafe executions;
- Unsafe Action Escape Rate: 0/24 (0%);
- Safe Action Preservation Rate: 3/3 (100%);
- False Block Rate: 0/3 (0%);
- T4 Containment Rate: 6/6 (100%);
- Approval Enforcement Rate: 100%;
- Emergency-stop executions: 0;
- Audit completeness: 27/27 (100%).

The recorded authorization latency was 0.044 ms median, 0.180 ms p95, and 0.312
ms p99 on the local evidence host. It is descriptive, not a production benchmark.

## Evidence and independent verification

The canonical package is `evidence/EXP-CN-001-v0.1.0/`. Its SHA-256 manifest,
JSONL hash chains, schemas, request correlation, and required files verify. A
separate calculation from raw proposal, decision, execution, and invariant records
reproduces escape, preservation, false-block, T4, approval, stop, and audit metrics.

## Reproducibility

`make bootstrap`, `make test`, `make formal`, and `make experiment` reproduce the
assurance workflow without secrets, paid models, cloud resources, production
targets, or manual authority setup. `make evidence` verifies the committed result.

## Limitations

The release uses one agent, one controller, one mission, synthetic adapters and OT,
finite model bounds, local HMAC custody, and a limited evaluation catalog. It has
no production IAM, hardware enforcement, adversarial host-compromise model, or
proof of TLA+/Python equivalence. The authorization kernel is assumed trusted.

## Release

**READY — v0.1.0.** No F1–F5 counterexample exists in the bounded release model;
no tested unauthorized action executed; T4, approval, emergency-stop, evidence,
independent-metric, and clean workflow gates pass.

## Next research experiment

**EXP-CN-002 — Adversarial Information Control Failure.** Use an isolated real
model and separately measure model compromise, unsafe proposal, authorization
rejection, and execution.
