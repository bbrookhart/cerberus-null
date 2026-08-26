# ADR-008: Synthetic container boundary

- Status: Accepted
- Date: 2026-08-26

## Decision

Ship only narrow in-memory adapters and run the service as an unprivileged, read-only container with all Linux capabilities dropped, no Docker socket, resource limits, and an internal network. No shell adapter exists.

## Consequences

Experiments cannot affect real systems by design. Container isolation does not prove resistance to every kernel or host vulnerability.
