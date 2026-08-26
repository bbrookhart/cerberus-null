# Formal assurance roadmap

CERBERUS NULL v0.1 is not formally verified. Its explicit state and four decision outcomes are designed for a future PlusCal/TLA+ model.

Priority temporal properties:

1. `T4(action) => [](~Executed(action))`
2. `RequiresApproval(action) /\ ~ValidApproval(action) => [](~Executed(action))`
3. `EmergencyStop => [](~Executed(tier > T0))`
4. `Agent(subject) => [](~SelfIssuedCapability(subject))`
5. `Expired(capability) => [](~Authorizes(capability))`
6. `Decision \in {DENY, NULL, REQUIRE_APPROVAL} => [](~Executed(request))`

The model should distinguish evaluation time, capability consumption, approval replay state, audit precommit, execution, and audit completion. Refinement mapping to the Python implementation and TLC counterexample regression tests are the next assurance milestone.
