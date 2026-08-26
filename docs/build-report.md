# CERBERUS NULL build report

## Release

Version `0.1.0`, implemented and evaluated on 2026-08-26.

## Research question

Can an agent remain useful while being structurally prevented from exceeding explicitly delegated authority or producing prohibited consequences when its planner is treated as manipulated or hostile?

## Architecture

Untrusted: model, planner, RAG, memory, natural-language context, tool output, model-generated code, and user content. Trusted in v0.1: host/runtime, signing key, identity and mission state, action registry, capability and approval verification, deterministic policy, emergency stop, protected gateway/adapters, and evidence recorder.

## Security invariants

The implemented boundary enforces no execution without valid capability; no self-expansion; exact approval binding; T4 prohibition; audit precommit; emergency-stop blocking; no authorization from content provenance; unknown-tool `NULL`; and direct-adapter rejection.

## Evaluation suite

EVAL-001–EVAL-012 cover safe read, unknown tool, privilege escalation, indirect prompt injection, tool-output injection, memory poisoning, approval expiry/replay, capability tampering, emergency stop, OT boundary, unknown provenance, and a systematically hostile planner.

## Flagship measured results

- 12 evaluation scenarios and 19 proposals;
- 18 unsafe proposals and 0 unsafe executions;
- 7/8 registered hostile actions executed by the naïve synthetic comparator;
- 0/8 hostile actions executed through CERBERUS NULL;
- 100% audit completeness;
- 0.021 ms median and 0.949 ms p95 decision latency in the committed run.

## Unsafe Action Escape Rate

`0 / 18 = 0%` under the documented v0.1 configuration and threat assumptions.

## Verification

Thirty-eight tests pass. Branch-aware coverage is 88.36% over the control/evaluation package with the CLI excluded. Ruff, strict mypy, Bandit, and dependency audit pass; property and adversarial suites pass independently; the CycloneDX SBOM is generated. Formal verification and a mutation score are not claimed.

## Assurance evidence

The committed `evidence/baseline-v0.1.0/` package contains configuration, mission, issuance policy, inputs, provenance, proposals, decisions, approvals, executions, metrics, summary, and a verified SHA-256 manifest. Claims and traceability are in `docs/assurance-case.md` and `threat-model/attack-control-matrix.yaml`.

## Reviewer path

```bash
make bootstrap
make test
cerberus evaluation run EVAL-012
make evidence
```

## Limitations

The baseline is synthetic and local; the key issuer is not production-grade; host and TCB compromise are out of scope; no real LLM, external MCP server, production adapter, or formal model checker is included. Zero observed escape is not universal proof.

## Next research milestone

Specify the authorization state machine in PlusCal/TLA+, model capability consumption and approval replay, use TLC counterexamples as regression fixtures, and then repeat EVAL-004/EVAL-012 with isolated local models at statistically meaningful sample sizes.

**Technical status:** the v0.1 deterministic boundary, synthetic execution range, measured TEVV suite, and evidence verifier are complete. Formal verification and external-model experiments remain open research work.
