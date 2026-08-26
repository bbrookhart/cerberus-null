# ADR-001: Threat and trust model

- Status: Accepted
- Date: 2026-08-26

## Decision

Treat the model, planner, memory, retrieval, tool output, model-generated code, and natural-language approval claims as untrusted. Assume the local host, runtime, signing key, static policy/registry, control-plane code, and human operator identity are trusted in v0.1.

## Consequences

Every consequential proposal requires independent structured authority. The result supports claims about a compromised planner, not a compromised host or trusted kernel.
