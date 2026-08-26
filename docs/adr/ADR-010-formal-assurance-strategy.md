# ADR-010: Formal assurance roadmap

- Status: Accepted
- Date: 2026-08-26

## Decision

Keep authority states and transitions explicit, test invariants with examples and Hypothesis in v0.1, and prepare a future TLA+/PlusCal model for the highest-value safety properties.

## Consequences

No formal-verification claim is made for v0.1. The implementation is structured to make later model checking meaningful rather than decorative.
