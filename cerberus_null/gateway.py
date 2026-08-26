"""The sole protected execution path (policy enforcement point)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cerberus_null.adapters import AdapterRegistry
from cerberus_null.authority import ApprovalVerifier, CapabilityBroker
from cerberus_null.evidence import EvidenceRecorder
from cerberus_null.models import (
    ActionEnvelope,
    ApprovalArtifact,
    Decision,
    ExecutionResult,
    ProvenanceRecord,
    sha256_json,
)
from cerberus_null.policy import PolicyDecisionPoint
from cerberus_null.registry import get_action_spec


class ExecutionGateway:
    def __init__(
        self,
        *,
        policy: PolicyDecisionPoint,
        adapters: AdapterRegistry,
        capabilities: CapabilityBroker,
        approvals: ApprovalVerifier,
        evidence: EvidenceRecorder | None = None,
    ) -> None:
        self._policy = policy
        self._adapters = adapters
        self._capabilities = capabilities
        self._approvals = approvals
        self._evidence = evidence

    def process(
        self,
        envelope: ActionEnvelope,
        *,
        provenance: tuple[ProvenanceRecord, ...],
        approval: ApprovalArtifact | None = None,
        now: datetime,
    ) -> ExecutionResult:
        authorization = self._policy.decide(
            envelope, provenance=provenance, approval=approval, now=now
        )
        audit_complete = False
        if self._evidence is not None:
            self._evidence.append(
                "proposals.jsonl",
                {
                    **envelope.model_dump(mode="json"),
                    "envelope_hash": sha256_json(envelope),
                },
            )
            for record in provenance:
                self._evidence.append("provenance.jsonl", record.model_dump(mode="json"))
            if approval is not None:
                self._evidence.append("approvals.jsonl", approval.model_dump(mode="json"))
            self._evidence.append("decisions.jsonl", authorization.model_dump(mode="json"))
            audit_complete = True

        if authorization.decision is not Decision.ALLOW:
            if self._evidence is not None:
                self._evidence.append(
                    "execution.jsonl",
                    {
                        "request_id": envelope.request_id,
                        "request_hash": envelope.request_hash,
                        "executed": False,
                        "decision": authorization.decision,
                        "reason_code": authorization.reason_code,
                    },
                )
            return ExecutionResult(
                request_id=envelope.request_id,
                decision=authorization.decision,
                executed=False,
                reason_code=authorization.reason_code,
                authorization=authorization,
                audit_complete=audit_complete,
            )

        spec = get_action_spec(envelope.action)
        if spec is None:  # defensive; policy already mediates this path
            raise RuntimeError("authorization inconsistency: unknown action allowed")
        capability = self._capabilities.decode_token(envelope.capability_token)
        if capability is None:
            raise RuntimeError("authorization inconsistency: malformed capability allowed")

        # INV-AUDIT-001: the authorization event is persisted before consequential execution.
        change: dict[str, Any] = self._adapters.execute(
            spec, envelope.resource, envelope.parameters
        )
        self._capabilities.consume(capability.capability_id)
        if approval is not None:
            self._approvals.consume(approval.approval_id)
        if self._evidence is not None:
            self._evidence.append(
                "execution.jsonl",
                {
                    "request_id": envelope.request_id,
                    "request_hash": envelope.request_hash,
                    "executed": True,
                    "decision": authorization.decision,
                    "environment_change": change,
                },
            )
        return ExecutionResult(
            request_id=envelope.request_id,
            decision=authorization.decision,
            executed=True,
            reason_code=authorization.reason_code,
            environment_change=change,
            authorization=authorization,
            audit_complete=audit_complete,
        )
