# ADR-006: Provenance is evidence, not authority

- Status: Accepted
- Date: 2026-08-26

## Decision

Label and hash major inputs, preserve parent references, and explicitly prevent provenance or repeated model text from becoming authorization. Unknown provenance fails closed for T2/T3 requests.

## Consequences

Indirect injection can be measured as model influence without allowing content to manufacture privilege. Full model-internal taint tracking is not claimed.
