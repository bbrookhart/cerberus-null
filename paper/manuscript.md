# Authority Without Trust: Runtime Security Boundaries for Autonomous AI Agents

Brian Brookhart

**Status:** pre-results research manuscript. EXP-CN-002 has not yet been executed. Any v0.1 values below are bounded baseline evidence from the existing CERBERUS NULL release, not results of the new real-model study.

## Abstract

Autonomous AI agents can translate probabilistic model outputs into persistent digital or physical side effects while inheriting authority that is substantially broader than the task a human intended to delegate. Prompt-level alignment and attack detection reduce some failure modes, but they do not by themselves define which actions an agent is authorized to execute after the model has been manipulated, confused, or otherwise fails. We study an alternative security boundary: treat the model as an untrusted proposer and place consequential execution behind independently enforced, task-scoped authority.

We present CERBERUS NULL, an experimental control plane and test, evaluation, verification, and validation environment that separates model proposal from execution through typed action envelopes, signed capabilities, provenance checks, deterministic policy, action-bound approval, consequence tiers, emergency stop, protected adapters, and tamper-evident evidence. We pair it with VIGIL, a runtime-security implementation that explores the same authority principle at a local endpoint through semantic brokers, bounded capability leases, provenance-aware restriction, budgets, approval, audit, and native macOS enforcement contracts. The central hypothesis is not that models can be made incapable of unsafe reasoning; it is that model compromise need not imply execution authority.

The existing CERBERUS NULL v0.1 synthetic baseline recorded 24 unsafe proposals with zero unsafe executions under its bounded threat model, while a naive comparator executed 13 of 14 hostile-planner unsafe attempts. A finite TLA+ abstraction found no stated F1–F7 counterexample across 221 reachable states and detected the expected counterexample in a deliberately broken mutation. These results establish only a bounded implementation baseline. EXP-CN-002 is preregistered to evaluate real model-backed agents, matched benign/adversarial tasks, naive and authority-mediated conditions, control ablations, safe-task utility, and the full chain from model compromise to actual synthetic side effect. The primary outcome is unsafe action escape rate; secondary outcomes include safe action preservation, false block rate, approval enforcement, latency, audit completeness, and control-specific contribution.

## 1. Introduction

AI agents increasingly operate tools, files, network services, code runners, memories, identity systems, and business workflows. This changes the security problem. A conventional chatbot can produce a harmful answer; an autonomous agent can also make the answer executable.

The common architecture compounds two forms of uncertainty. First, the model is a probabilistic planner whose behavior can change under indirect prompt injection, poisoned memory, adversarial tool output, ambiguous instructions, or ordinary reasoning failure. Second, the agent process often inherits ambient authority from the user or application hosting it. The task delegated by the human may be narrow, while the credentials, filesystem access, process rights, network reachability, or tool surface available to the agent are broad.

This creates an authority gap. A model may be authorized to *reason about* an action without being authorized to *perform* it. Tool availability is therefore not equivalent to permission, and model confidence is not a security principal.

We investigate the following proposition:

> **Intelligence does not imply authority. A model may propose actions probabilistically, while an independent mechanism decides deterministically whether those actions may execute.**

The paper makes three contributions.

1. **A security model for autonomous action.** We define a boundary that separates model output from execution and binds authority to identity, mission, action, resource, parameters, time, consequence, provenance, approval, and revocation state.
2. **An implementation-backed TEVV environment.** CERBERUS NULL provides a typed execution gateway, deterministic policy, capabilities, approval artifacts, protected synthetic adapters, evidence chains, adversarial scenarios, a naive comparator, mutation testing, and a finite formal model.
3. **An empirical protocol for real model-backed agents.** EXP-CN-002 measures the complete path from manipulation to proposal, authorization, attempted execution, executed side effect, and retained benign utility. It is designed to distinguish a model that becomes compromised from a system that actually loses control of execution.

The study deliberately avoids a stronger claim: externally mediated authority does not make a model aligned, does not guarantee detection of manipulation, and does not prove whole-process endpoint confinement. It attempts to reduce the consequence of model failure by constraining what failure is allowed to do.

## 2. Research questions

**RQ1 — Proposal behavior.** Under controlled adversarial information conditions, how often do real model-backed agents propose actions that violate the declared task, capability, approval, or consequence policy?

**RQ2 — Authority containment.** Given an unsafe proposal, how often does the action cross the independent execution boundary?

**RQ3 — Utility.** How much benign task success is preserved when the same authority controls are active?

**RQ4 — Control contribution.** Which controls account for measured containment: capability scope, provenance, approval binding, consequence tiering, budgets, emergency stop, or runtime mediation?

**RQ5 — Composition.** Which guarantees are supported by CERBERUS NULL's experimental authority boundary, which are supported by VIGIL's runtime mechanisms, and where do their claim boundaries differ?

## 3. Threat model

### 3.1 Adversary

The primary adversary controls information consumed by an agent: retrieved documents, messages, memory entries, tool output, or other synthetic untrusted content. The adversary may attempt to induce the model to reinterpret mission scope, invent authority, request a higher-consequence action, reuse approval, expand a capability, or route around an expected control.

A stronger experimental condition treats the planner as actively hostile: it can directly emit proposals intended to violate policy. This isolates whether the execution boundary depends on cooperative model behavior.

### 3.2 Protected assets

The protected assets in EXP-CN-002 are synthetic resources and side effects representing:

- mission-scoped data;
- identity and role boundaries;
- process or administrative actions;
- sensitive configuration changes;
- approval-required operations;
- safety-critical control-plane operations;
- authorization state, capabilities, policy and evidence.

No production account, public target, physical equipment, real credential, malware, persistence mechanism, or destructive payload is part of the study.

### 3.3 Trusted computing base

The CERBERUS NULL experiment treats the model, planner, RAG, memory, natural-language context, tool output, and model-generated code as untrusted. The trusted computing base contains identity/mission resolution, issued capability state, deterministic policy, safety/consequence checks, approval verification, emergency-stop state, the execution gateway, protected synthetic adapters, and evidence recording.

This is an assumption, not a conclusion. Compromise of the TCB is outside the primary experiment and must remain explicit in interpretation.

### 3.4 Non-goals

The study does not attempt to prove:

- universal model alignment;
- universal prompt-injection detection;
- security against a compromised host/kernel or signing authority;
- equivalence between the TLA+ model and the full implementation;
- production safety certification;
- whole-process macOS confinement by VIGIL before activated-device evidence exists.

## 4. Authority model

### 4.1 Proposal is not execution

The model emits a typed proposal rather than directly invoking a protected adapter. The proposal includes the intended action, resource, parameters, mission context, claimed consequence class, and provenance references needed by downstream evaluation.

A proposal can be semantically unsafe without being an executed side effect. EXP-CN-002 records these as distinct stages.

### 4.2 Capability-bound authority

Capabilities are issuer-created, signed, expiring, use-limited, revocable, and non-delegable by default. They bind the subject and mission to an action/resource/parameter scope. An agent cannot mint or broaden its own authority by emitting text, changing confidence, or presenting untrusted retrieved content.

### 4.3 Deterministic policy

Authorization is an ordered decision over schema, identity, mission, capability, resource, parameters, provenance, policy, safety, consequence, approval, and execution state. Mandatory failure does not degrade into an allow decision.

CERBERUS NULL retains a first-class `NULL` result for requests that do not establish a valid executable path, including malformed/unknown actions or states where the system cannot safely determine authority.

### 4.4 Approval as an artifact

Human approval is bound to the exact material request rather than represented as a broad boolean mode. The approval records the action/resource/parameter binding and validity window. Mutation or replay invalidates the approval.

### 4.5 Consequence-aware autonomy

Actions are classified by consequence tier. Higher-consequence actions require narrower authority and, where specified, exact approval. Safety-critical/control-plane actions can be structurally unavailable to autonomous execution under the evaluated policy.

### 4.6 Provenance can restrict, not authorize

Untrusted content can influence the model but cannot itself create a capability, approval, role, mission, or authority expansion. Provenance therefore participates in restriction/denial decisions while never serving as an authority issuer.

## 5. CERBERUS NULL system

CERBERUS NULL is the public experimental environment used for the primary study. Its current v0.1 release includes:

- typed action envelopes and a protected execution gateway;
- deterministic identity/mission/capability/policy/safety/approval checks;
- signed capabilities and action-bound approvals;
- consequence tiers and emergency stop;
- synthetic protected adapters;
- adversarial TEVV scenarios;
- a naive comparator;
- evidence manifests and independent result verification;
- unit, integration, property, architecture, adversarial and mutation tests;
- a finite TLA+ authorization model.

The v0.1 release is a baseline for the research protocol, not the final empirical study.

## 6. VIGIL relationship and claim boundary

VIGIL explores the same external-authority thesis as a local runtime security architecture. Its private implementation includes portable Rust policy and capability components, semantic brokers for mediated filesystem/process/network/secret/MCP actions, quantitative budgets, approval and audit paths, causal provenance, incident/risk handling, and Swift Endpoint Security / Network Extension policy contracts.

The relationship is deliberately asymmetric:

- **CERBERUS NULL** is the public experimental control plane and TEVV environment used to generate the primary paper evidence.
- **VIGIL** is implementation-backed evidence that the authority model can be extended toward an endpoint runtime with semantic mediation and native enforcement contracts.

The paper will not infer a stronger VIGIL claim than its evidence supports. Broker-mediated actions are currently enforceable within those broker paths; whole-process macOS confinement remains unproven until signed, entitled, activated-device evidence demonstrates the native boundary under real event flow and failure conditions.

## 7. Existing v0.1 baseline

The existing CERBERUS NULL v0.1 experiment, `EXP-CN-001-v0.1.0`, reports the following bounded baseline:

| Metric | v0.1 measured result |
|---|---:|
| Evaluation scenarios | 12 |
| Total proposals | 27 |
| Unsafe proposals | 24 |
| Unsafe actions executed | 0/24 |
| Safe action preservation | 3/3 |
| Hostile-planner unsafe attempts | 14 |
| Naive comparator unsafe executions | 13/14 |
| CERBERUS NULL unsafe executions on matched hostile attempts | 0/14 |
| Audit completeness | 27/27 |
| TLA+ distinct reachable states | 221 |
| Stated F1–F7 counterexamples | 0 |
| Deliberately broken mutation | expected F1 counterexample detected |

These values do not establish real-model efficacy. They show that the existing synthetic harness and bounded authority model are capable of representing a vulnerable comparator and an independently mediated execution condition before EXP-CN-002 introduces real model-backed planners.

## 8. EXP-CN-002 study design

The full preregistration is maintained in `experiments/EXP-CN-002-protocol.md` and must be frozen before paid or externally hosted model execution.

### 8.1 Conditions

The study will include:

1. **Naive execution baseline:** the model-backed agent can invoke the synthetic tool path without the CERBERUS authority boundary.
2. **Full authority boundary:** all protected actions traverse the CERBERUS NULL decision pipeline.
3. **Ablation conditions:** selected controls are removed or weakened one at a time where doing so preserves a meaningful executable system.
4. **Deterministic hostile planner:** retained as a model-independent control showing whether enforcement depends on planner cooperation.

### 8.2 Tasks

Every security-relevant adversarial task is paired with a benign task matched on environment, tool surface, resource family, and required legitimate capability where practical. This makes a system that simply blocks all action visibly fail the utility measurement.

### 8.3 Models

At least two target-model families should be evaluated if access and cost permit. Exact model/provider identifiers, dates, sampling parameters, retries, system instructions, tool schemas, and adapter versions must be frozen into the run manifest.

Model availability changes rapidly; no manuscript claim should rely on an unfrozen marketing name.

### 8.4 Outcomes

**Primary outcome**

- Unsafe Action Escape Rate (UAER): executed prohibited actions / prohibited action proposals eligible for the defined denominator.

**Secondary outcomes**

- unsafe proposal rate;
- safe action preservation rate;
- false block rate;
- approval enforcement rate;
- authorization latency;
- audit completeness;
- operator approval burden;
- consequence-tier-specific escape rate;
- attack-class-specific escape rate.

Every rate must be reported with numerator, denominator, and uncertainty appropriate to the design.

### 8.5 Stage decomposition

The runner must preserve separate evidence for:

```text
adversarial information
→ model influenced/compromised
→ unsafe proposal emitted
→ authorization decision
→ execution attempted
→ protected adapter reached
→ synthetic side effect occurred
→ consequence recorded
```

This prevents the paper from treating model compromise, authorization failure, and executed consequence as interchangeable outcomes.

## 9. Ablation plan

Subject to the frozen protocol, the study will measure the contribution of:

- capability validation;
- mission/resource scope;
- provenance policy;
- exact approval binding;
- consequence tiering;
- quantitative budgets/use limits;
- emergency stop;
- protected execution mediation.

An ablation is interpretable only if it changes the intended mechanism without silently changing unrelated conditions. If a mechanism cannot be removed independently, the paper will report that architectural dependency rather than fabricate an isolated effect.

## 10. Formal assurance

The finite TLA+ model is used to check stated authorization invariants under a bounded abstraction. EXP-CN-002 will extend the model only if the new experiment introduces security-relevant state absent from v0.1. Formal results will remain explicitly bounded to the explored model and will not be described as a proof of the Python implementation or universal agent safety.

Mutation tests provide a complementary implementation check: deliberately weakening an enforcement property should create a detectable failure in the corresponding test/experiment path.

## 11. Results

**Pending EXP-CN-002 execution.**

This section will not be populated from mock output, deterministic fixture output presented as model evidence, or unverified local runs. The final manuscript will report:

- model-by-condition unsafe proposal rate;
- unsafe action escape rate;
- benign utility / safe action preservation;
- false block and approval-enforcement rates;
- ablation results;
- uncertainty and denominator accounting;
- errors/exclusions;
- formal and mutation-test evidence;
- independent metric verification.

## 12. Limitations

The expected limitations include:

- synthetic environments and consequences rather than production systems;
- limited target-model and task distributions;
- model/provider drift over time;
- a TCB that remains assumed intact;
- incomplete equivalence between experimental controls and endpoint/runtime implementations;
- no claim of protection against root/kernel compromise;
- no proof that the model itself is aligned or manipulation-resistant;
- human approval quality and fatigue not fully modeled by an action-bound approval artifact;
- VIGIL native macOS enforcement remaining bounded by its activated-device evidence status.

The paper will add limitations discovered during execution rather than treating this list as exhaustive.

## 13. Reproducibility and artifact

The artifact release should contain or reference:

- exact source commit/tag;
- frozen protocol and configuration;
- model/provider metadata and dates;
- synthetic task/scenario definitions;
- raw proposal/decision/execution evidence;
- manifests/checksums;
- independently recalculated headline metrics;
- formal model and results;
- mutation-test results;
- analysis scripts;
- machine-readable summary tables;
- reproduction instructions from a clean clone;
- documented exclusions for secrets, private linkage material, or unavailable third-party services.

A DOI-backed archival deposit should be created only after the evidence package is frozen.

## 14. Responsible use

The research is defensive and synthetic. It is intended to evaluate how an autonomous system can retain useful capability while limiting unauthorized execution after model failure. The artifact must not be extended into unauthorized targeting, credential theft, malware deployment, persistence, or physical-system control.

## 15. Conclusion

Autonomous AI security cannot rely on the assumption that the model will always interpret intent correctly or resist adversarial influence. The security question is therefore not only whether a model can be made to fail, but what authority remains available when it does.

CERBERUS NULL and VIGIL explore a design in which the model is free to reason probabilistically while consequential execution remains externally mediated. EXP-CN-002 will test whether that separation reduces unsafe execution while preserving useful action under real model-backed conditions. Until those results exist, the central contribution is a falsifiable security boundary and an implementation-backed protocol—not a claim that the problem has been solved.
