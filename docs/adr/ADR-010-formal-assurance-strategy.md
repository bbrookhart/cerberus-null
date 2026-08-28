# ADR-010: Formal assurance strategy

- Status: Accepted
- Date: 2026-08-26

## Decision

Specify the authorization state machine in TLA+ and use TLC to exhaustively check
F1-F7 within documented finite bounds. Pair this abstraction with Hypothesis,
integration, architecture, adversarial, and negative-mutation tests because model
checking does not establish Python implementation equivalence.

## Consequences

v0.1 claims only that the bounded model satisfies its invariants over all reachable
states in the committed configuration. A known-broken model must generate an F1
counterexample. No universal-security or formally-verified-agent claim is allowed.
