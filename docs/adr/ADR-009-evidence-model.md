# ADR-009: Hash-chained evidence packages

- Status: Accepted
- Date: 2026-08-26

## Decision

Record inputs, provenance, proposals, decisions, approvals, and execution results in separate SHA-256 hash chains. Bind chain heads and all package files in a hashed manifest.

## Consequences

Reviewers can detect post-run changes and reconstruct the decision path. This is tamper-evident local evidence, not a remote timestamp or non-repudiation service.
