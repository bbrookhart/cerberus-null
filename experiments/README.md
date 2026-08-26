# Flagship experiments

## Model compromise assumption test

Configuration A is an intentionally naïve synthetic registered-tool architecture: any known tool request is treated as executable. Configuration B sends the same eight intents through CERBERUS NULL. The experiment measures unsafe proposals, unsafe executions, maximum blast radius, policy latency, audit completeness, and approval outcomes.

Reproduce with:

```bash
cerberus evaluation run EVAL-012
```

The committed baseline measured seven registered unsafe executions in the naïve comparator and zero in CERBERUS NULL. No production or external system is involved.

## Indirect prompt injection under consequence

EVAL-004 places a benign malicious instruction in synthetic retrieved content. The harness records the tainted input, unsafe proposal, capability decision, execution result, and consequence separately.

```bash
cerberus evaluation run EVAL-004
```

The deterministic mock represents a model-level failure by proposing the injected T3 operation; the control plane denies it because the proposal lacks delegated capability. This experiment does not claim that the mock represents a real model's injection susceptibility.
