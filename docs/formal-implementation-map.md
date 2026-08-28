# Formal-to-implementation map

The TLA+ model is an abstraction of the authorization state machine, not a
translation of the Python program. This map makes the correspondence and the
remaining proof gap explicit.

| Formal concept | Python state/control | Implementation | Verification |
|---|---|---|---|
| `requestState` | request lifecycle inferred from result | `ExecutionGateway.process` | gateway integration and evidence-correlation tests |
| `action`, `resource` | immutable typed envelope fields | `ActionEnvelope` | model-validation and property tests |
| `capabilityPresented` | bearer capability token | `CapabilityGrant`, `CapabilityBroker.decode_token` | capability unit tests |
| `capabilityIssuer` | registered external issuer | `CapabilityBroker._grants`, signature verification | self-issued/tampering tests; EVAL-003/008/012 |
| `capabilityActive` | valid, unrevoked, unexpired, unexhausted grant | `CapabilityBroker.validate` | authority unit/property tests |
| `approvalState` | missing, valid, expired, replayed, forged, or mismatched artifact | `ApprovalVerifier` | approval unit tests; EVAL-007/011/012 |
| `requestHash`, `approvalHash` | canonical exact-request digest | `ActionEnvelope.request_hash`, `ApprovalArtifact.request_hash` | binding tests and EVAL-011 |
| `emergencyStop` | independent persisted stop flag | `EmergencyStop` | emergency-stop unit/property tests; EVAL-009 |
| `decision` | four-valued authorization result | `Decision`, `PolicyDecisionPoint` | policy tests and every evaluation decision record |
| `executed` | protected adapter result | `ExecutionGateway`, `ExecutionResult.executed` | integration, architecture, and adversarial tests |
| `auditRecorded` | pre-execution in-memory audit plus optional hash-chained record | `ExecutionGateway.audit_log`, `EvidenceRecorder` | gateway/evidence tests and audit-completeness metric |

## Claim traceability

| Claim | Formal property | Control | Tests/evaluation | Preserved evidence |
|---|---|---|---|---|
| CN-C1 exact authority precedes execution | F1 | policy, capability verifier, gateway | property suite; EVAL-002/003/008/012 | `decisions.jsonl`, `executions.jsonl`, `invariants.jsonl` |
| CN-C2 approval binds the exact request | F2, F7 | approval verifier | approval suite; EVAL-007/011/012 | `approvals.jsonl`, `invariants.jsonl` |
| CN-C3 stop blocks consequential execution | F3 | independent emergency stop | stop property suite; EVAL-009 | decision and invariant records |
| CN-C4 agent cannot self-escalate | F4 | registered signed grants | capability suite; EVAL-003/008/012 | capability and decision records |
| CN-C5 T4 has no autonomous path | F5 | closed registry and policy | T4 property suite; EVAL-010/012 | decision, execution, and metric records |

## Known abstraction differences

- TLA+ models finite action classes and resources; Python evaluates concrete
  typed names, patterns, parameters, timestamps, and signatures.
- TLA+ treats cryptographic verification as a Boolean authority predicate; it
  does not model HMAC cryptanalysis or key custody.
- TLA+ records logical audit precommit; Python evidence adds file hashes and
  per-stream hash chains.
- TLC does not prove implementation equivalence. Property, integration,
  architecture, mutation, and adversarial tests are separate evidence layers.
