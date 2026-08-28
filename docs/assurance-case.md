# CERBERUS NULL v0.1 assurance case

## CN-C1 — exact authority precedes protected execution

**Claim.** Under the documented threat model, an agent cannot execute a protected
operation unless the independent authorization architecture establishes valid
authority for that exact request.

**Argument.** The immutable action envelope crosses one policy decision point and
one execution gateway. Protected adapters require the gateway permit. Unknown,
malformed, unscoped, expired, revoked, stopped, and prohibited requests have no
execution transition.

**Evidence.** F1; P1 properties; architecture and gateway tests; EVAL-002/003/008/012;
EXP-CN-001; proposal, decision, execution, and invariant records.

## CN-C2 — approval is exact, fresh, and single-use

**Claim.** Approval-required actions cannot execute without an independently issued
approval bound to the exact request.

**Argument.** Approval signs the request, mission, action, resource, controller,
parameter digest, and validity window. The verifier rejects forgery, mutation,
expiry, replay, and wrong controller.

**Evidence.** F2/F7; approval unit/property tests; EVAL-007/011/012; approval and
invariant evidence streams.

## CN-C3 — emergency stop preserves human control

**Claim.** Engaging emergency stop prevents consequential execution.

**Argument.** Only an active registered human may engage or release stop. Policy
returns `NULL` for actions above T0 while engaged; formal transitions also admit
stop engagement after request creation.

**Evidence.** F3; emergency-stop unit/property tests; EVAL-009; zero emergency-stop
executions in independently reproduced metrics.

## CN-C4 — the agent cannot expand its own authority

**Claim.** The planner cannot mint or broaden executable capability.

**Argument.** Only stored issuer-created grants whose signed canonical payload
matches the presented token become active. Grants are non-delegable, scoped,
expiring, revocable, and use-limited.

**Evidence.** F4; capability unit/property tests; EVAL-003/008/012; F1 negative
formal mutation.

## CN-C5 — T4 has no autonomous path

**Claim.** T4 actions cannot execute autonomously under v0.1 policy.

**Argument.** Every T4 registry entry is non-autonomous and deterministic policy
returns `NULL` before capability or model confidence can establish a path.

**Evidence.** F5; T4 registry/architecture tests; Hypothesis T4 properties;
EVAL-010/012; 6/6 T4 containment in the canonical evidence.

## Assumptions and confidence boundary

The host, runtime, signing key, identity and mission stores, registry, policy,
gateway, adapters, emergency stop, and evidence recorder remain trustworthy. The
TLA+ model is finite and does not prove Python equivalence. The adversarial suite
is synthetic and finite. Therefore the supported conclusion is:

> The bounded authorization model satisfies F1–F7 over all reachable modeled
> states, and no tested unauthorized request crossed the protected implementation
> boundary under EXP-CN-001 and EVAL-001–012.

This is not a claim of universal agent safety.
