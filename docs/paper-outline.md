# Separating Intelligence from Authority

## Formally constrained capability enforcement for autonomous AI agents

1. Introduction: model intelligence and system authority are different security
   properties.
2. Related work: capability security, reference monitors, zero trust, assured
   autonomy, agent tool-use security, and AI TEVV.
3. Threat model: hostile planner; trusted authorization kernel; scoped exclusions.
4. Architecture: typed proposals, external authority, deterministic policy,
   complete mediation, human stop, and evidence precommit.
5. Formal model: state abstraction, F1-F7, finite bounds, TLC methodology, and
   negative mutation validation.
6. Implementation: Python authority kernel, signed capabilities, approval binding,
   protected synthetic adapters, and evidence chain.
7. EXP-CN-001: same hostile planner under naive and CERBERUS conditions.
8. Results: unsafe escape, safe preservation, false blocks, T4 containment,
   approval enforcement, audit completeness, and latency.
9. Assurance argument: claim-to-formal-to-code-to-test-to-evidence traceability.
10. Threats to validity and limitations.
11. Discussion: why model compromise and system compromise should be measured
    separately.
12. Future work: EXP-CN-002 with an isolated real model and adversarial information
    inputs.

The contribution language must remain bounded: the authorization state machine was
formally specified and model-checked; the implementation resisted the documented
adversarial sequences. The AI agent itself was not formally verified.
