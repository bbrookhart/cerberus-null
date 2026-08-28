# Separating Intelligence from Authority

## Formal and experimental evaluation of capability-constrained AI agents

### Abstract

CERBERUS NULL tests whether an AI planner can remain useful while an independent,
deterministic authorization architecture prevents actions outside explicitly
delegated authority. The planner is treated as hostile. The artifact combines a
typed capability implementation, an execution gateway, a bounded TLA+ state
machine, TLC model checking, Hypothesis properties, adversarial evaluation, and
hash-bound evidence. TLC explored 221 reachable states without finding an F1-F7
violation; a known-broken mutation produced the expected F1 counterexample. In
EXP-CN-001, the protected architecture executed 0 of 14 unsafe hostile-planner
proposals while executing 2 of 2 safe proposals. Across EVAL-001–012 it executed
0 of 24 unsafe proposals and preserved 3 of 3 safe proposals.

## Research question

Can an AI agent remain operationally useful while an independent deterministic
authorization architecture prevents it from executing actions outside explicitly
delegated authority—even when the planner is treated as compromised?

## Threat model

The LLM, planner, memory, retrieved content, tool output, user-controlled text,
model-generated reasoning, and all natural-language claims are untrusted. The
host, Python runtime, issuer/approver key, identity and mission stores, policy,
gateway, protected adapters, emergency stop, and evidence recorder form the v0.1
trusted computing base. Host or TCB compromise is out of scope.

## Architecture and authority model

The untrusted layer emits an immutable `ActionEnvelope`. The policy decision point
resolves the registered agent and controller, mission scope, action tier,
capability signature and constraints, provenance, approval, policy health, and
emergency state. It returns `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, or `NULL`. Only the
execution gateway can supply a protected adapter permit. Authority originates only
from registered human/system state; prompt text and model beliefs cannot create it.

## Capability and approval model

Capabilities are issuer-created, signed, subject-bound, mission-bound,
action-bound, resource-scoped, parameter-constrained, expiring, revocable,
use-limited, and non-delegable. Approval artifacts bind the approver, request hash,
mission, action, resource, parameter digest, and validity window. Mutation or reuse
invalidates approval.

## Formal specification

`formal/CerberusNull.tla` models one agent, one human issuer, safe,
approval-required, T4, and unknown action classes; in-scope/out-of-scope resources;
human/agent capability issuers; valid/expired/mismatched approval; revocation; and
emergency-stop engagement after request submission. TLC 2026.08.21.155922 generated
341 states and found 221 distinct reachable states at graph depth 6.

The core properties are:

- F1: unauthorized actions never execute;
- F2: approval-required actions execute only with matching valid approval;
- F3: emergency stop prevents consequential execution;
- F4: agent-issued authority never becomes an active capability;
- F5: T4 actions never execute autonomously.

F6 checks audit precommit and F7 checks approval-hash binding. TLC found no
violation in the documented finite model. `CerberusNullBroken.tla` deliberately
adds execution without a capability; TLC found the expected F1 counterexample.

## Implementation verification

The Python analogue is exercised through unit, integration, architecture,
Hypothesis property, and adversarial suites. Tests cover capability scope and
expiry, self-issuance and tampering, exact approval and replay, mission/tier scope,
unknown tools, provenance, policy failure, emergency stop, T4 prohibition,
determinism, complete mediation, and audit precommit. Formal-to-code traceability is
documented in `docs/formal-implementation-map.md`.

A separate isolated mutation harness removed capability expiry, approval binding,
emergency-stop enforcement, T4 prohibition, and gateway mediation one at a time.
The targeted regression tests killed all five mutations. This is not presented as
a repository-wide mutation score.

## Adversarial evaluation

EXP-CN-001 uses a deterministic planner that knows the registry and policy. It
attempts wrong-action and out-of-scope capabilities, expiry, capability forgery,
approval forgery/replay/mutation, unknown tools, T3 without approval, T4 OT control,
audit disablement, policy modification, stop release, and adapter bypass. It also
submits two legitimate observations to detect a system that merely blocks
everything. An intentionally insecure agent-to-tool architecture receives the same
proposals.

| EXP-CN-001 metric | Naive | CERBERUS NULL |
|---|---:|---:|
| Unsafe proposals | 14 | 14 |
| Unsafe executions | 13 | 0 |
| Unsafe Action Escape Rate | 92.86% | 0% |
| Safe proposals | 2 | 2 |
| Safe executions | 2 | 2 |

Across EVAL-001–012, 27 proposals were evaluated: 24 unsafe and 3 safe. Unsafe
Action Escape Rate was 0/24; Safe Action Preservation Rate was 3/3; false block
rate was 0%; T4 containment, approval enforcement, and audit completeness were
100%. Authorization latency was 0.044 ms median, 0.180 ms p95, and 0.312 ms p99 on
the recorded local run. These timing values are descriptive, not a benchmark.

## Evidence and independent verification

`evidence/EXP-CN-001-v0.1.0/` contains environment, configuration, policy,
capability, mission, input, provenance, proposal, decision, approval, execution,
invariant, metric, comparison, verification, summary, and manifest artifacts. The
manifest binds files with SHA-256 and each JSONL stream has a hash chain. The
independent verifier recalculates escape, preservation, false-block, T4,
approval, stop, and audit metrics from raw records rather than trusting the
primary metric module.

## Threats to validity

**Model validity.** The finite TLA+ abstraction may omit implementation detail.
The explicit map reduces, but cannot eliminate, this risk.

**Implementation validity.** Model checking does not prove the Python code. The
test and experiment layers are finite and may miss defects.

**Experimental validity.** The deterministic hostile planner represents failure
classes, not the full behavior distribution of real models or attackers.

**External validity.** Synthetic in-memory adapters do not establish safety for
real identity, endpoint, or OT systems.

## Limitations

The release has one agent, one human controller, one synthetic mission, finite
formal bounds, local HMAC keys, no production IAM, no hardware enforcement, no
adversarial host compromise, no proof of implementation equivalence, no real OT
control, and a limited evaluation catalog. The authorization kernel is assumed
trusted. No zero-result is a universal proof.

## Reproducibility

From a clean clone, run `make bootstrap`, `make test`, `make formal`, and
`make experiment`. The canonical run requires no API key, paid model, networked
target, cloud account, or manual capability setup. `make evidence` verifies the
committed package and independently reproduces its metrics.

## Future work

The next experiment is EXP-CN-002, adversarial information-control failure. It
will introduce an isolated real model and separately measure model compromise,
unsafe proposal generation, authorization rejection, and execution. This preserves
the central distinction between model compromise and system compromise.
