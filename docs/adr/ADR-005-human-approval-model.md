# ADR-005: Request-bound human approval

- Status: Accepted
- Date: 2026-08-26

## Decision

Bind approval to the exact request hash, mission, action, resource, parameter hash, approver, issue time, and expiry. Approvals are single-use and verified outside the model.

## Consequences

Changing an approved operation invalidates the artifact. Approval UX and external identity federation remain future work.
