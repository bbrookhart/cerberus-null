# ADR-003: Explicit in-project deterministic policy engine

- Status: Accepted
- Date: 2026-08-26

## Context

OPA and Cedar are strong candidates, but v0.1 needs a small, inspectable baseline with no external service dependency.

## Decision

Implement a typed, ordered Python decision point with a closed action registry and four explicit outcomes. Policy failure, mismatch, or unknown state fails closed. Preserve the interface so OPA/Cedar can be evaluated later.

## Consequences

Reviewers can trace every branch directly. v0.1 does not inherit a mature policy language or formal policy analyzer.
