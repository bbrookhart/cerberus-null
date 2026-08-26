# ADR-004: Signed scoped capabilities

- Status: Accepted
- Date: 2026-08-26

## Decision

Use explicit signed grants bound to subject, mission, action, resource, parameters, time, use count, approval requirement, and non-delegability. RBAC alone is insufficient.

## Consequences

Tool visibility does not create authority, and replay/tampering can be tested independently. Distributed delegation is deferred.
