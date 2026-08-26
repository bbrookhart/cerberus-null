# Capability model

Capabilities are signed, explicit, inspectable, non-delegable v0.1 artifacts. Each grant binds:

- issuer and subject identity;
- mission and action;
- resource glob patterns;
- optional permitted parameter values;
- validity interval and maximum use count;
- human-approval requirement;
- a signature over the canonical payload.

The broker retains the issued grant and compares it with the presented token before verifying the signature. A self-issued, modified, expired, exhausted, revoked, wrong-subject, wrong-mission, wrong-action, wrong-resource, or wrong-parameter grant is denied. Consumption occurs only after an authorized adapter execution.

The HMAC implementation provides testable artifact binding in one local trusted domain. v0.1 does not solve distributed key custody, workload attestation, delegation chains, or cross-organization federation.
