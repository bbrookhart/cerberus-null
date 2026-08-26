# Provenance model

Inputs carry one of six labels: `TRUSTED_SYSTEM`, `TRUSTED_OPERATOR`, `INTERNAL_VERIFIED`, `EXTERNAL_UNTRUSTED`, `MODEL_GENERATED`, or `UNKNOWN`. Each record includes a source ID, content hash, observation time, and optional parent references.

Provenance describes where information came from; it never grants authority. External data may influence a proposal, but the proposal must still satisfy the independent mission, capability, policy, safety, and approval checks. Unknown or absent provenance causes T2/T3 requests to resolve to `NULL` in strict v0.1 policy.

The current implementation records lineage but does not perform full taint propagation through model internals. That is a planned research extension.
