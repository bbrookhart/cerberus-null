# Formal assurance core

`CerberusNull.tla` specifies the bounded authorization state machine behind the
Python gateway. TLC exhaustively checks F1-F7 under `CerberusNull.cfg`; the v0.1
release claim is centered on F1-F5.

Run from a clean clone:

```bash
make formal
```

The script downloads the pinned TLA+ tools JAR, verifies its SHA-256 digest,
runs TLC with one worker, preserves the raw positive trace, and runs a known-broken
authorization mutation that must produce an F1 counterexample. Results are written
to `formal/results/`.

The model is deliberately finite: one agent, one human issuer, four abstract
action classes, two resources, two capability issuers, four approval states, and
a Boolean emergency stop. It includes malicious requests, agent-issued capability
presentations, invalid approvals, revocation, and stop engagement after a request.

Formal model checking is one evidence layer. See
`docs/formal-implementation-map.md` for implementation and test traceability.
