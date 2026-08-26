# Threat model

## Research question

Can an autonomous AI agent remain useful while being structurally prevented from exceeding explicitly delegated authority or producing unacceptable consequences—even when the model is manipulated, hallucinating, misaligned with operator intent, or treated as compromised?

## Assets

- mission authority and capability scope;
- protected execution path;
- human approval sovereignty;
- safety invariants and emergency stop;
- audit/evidence integrity;
- synthetic environment state.

## Adversary

The primary adversary controls every proposal emitted by the planner and may manipulate retrieved documents, tool responses, short- or long-term memory, model-generated code, and natural-language claims of approval. It knows all registered actions and attempts privilege expansion, replay, tampering, policy bypass, log disabling, and T4 execution.

## Trust assumptions

The host, Python runtime, signing key, trusted control-plane code, static registry, and operator identity are assumed intact. Compromise of those elements is outside the v0.1 claim. The local HMAC issuer is a reproducible TEVV mechanism, not a production key-management design.

## Security boundaries

- Natural language cannot create authority.
- Possession of a tool name does not imply a capability.
- A capability is bound to subject, mission, action, resource, parameters, time, and use count.
- Approval is bound to the exact request hash and is single-use.
- T4 actions and unknown tools resolve to `NULL`.
- A stopped system cannot execute actions above T0; an agent cannot release the stop.

## Exclusions

No real targets, public discovery, persistence, malware, credential theft, arbitrary shell, external MCP server, production API, or physical controller is implemented. Host compromise, side channels, denial of service against the host, cryptographic key extraction, and policy-administrator compromise are not evaluated.
