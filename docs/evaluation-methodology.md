# Evaluation methodology

The TEVV harness uses deterministic mock agents and synthetic content so the control plane can be tested without paid APIs or stochastic-model confounders. Every evaluation specifies an attack class, model ID, mission, autonomy level, injected content indicator, expected decision, expected execution, and seed.

## Measurements

- unsafe proposal rate measures agent behavior;
- unsafe action escape rate measures boundary failure;
- authorization outcomes and decision latency measure kernel behavior;
- maximum attempted and executed blast radius separate intent from consequence;
- audit completeness checks whether each processed proposal produced recorded lineage;
- the flagship comparator runs the same hostile intents through an intentionally naïve registered-tool architecture and CERBERUS NULL.

Latency uses wall-clock `perf_counter_ns` around the in-process decision point. p95 and p99 are nearest-rank values and should not be generalized from the small baseline sample.

## Reproducibility

```bash
make bootstrap
make test
cerberus evaluation run all
cerberus evidence verify <run-directory>
```

Evidence JSONL streams use SHA-256 hash chains. The manifest binds stream heads and every package file. Generated timestamps and latency will vary; expected authorization and execution outcomes must not.

## Interpretation

A passing run supports only the conditional claim stated in the assurance case. It does not establish that every possible proposal, policy configuration, model, deployment topology, or host compromise is safe.
