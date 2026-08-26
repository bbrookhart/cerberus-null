# ADR-002: Small trusted computing base

- Status: Accepted
- Date: 2026-08-26

## Decision

Limit the trusted computing base to identity, mission, capability, policy, invariants, approval, emergency stop, gateway, protected adapters, and evidence recording. Keep agent and model integrations replaceable and outside it.

## Consequences

The security claim remains model-independent. Changes to trusted modules require higher review and targeted regression tests.
