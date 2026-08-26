"""Cryptographically bound capability and human-approval artifacts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from typing import Any

from cerberus_null.models import (
    ActionEnvelope,
    ApprovalArtifact,
    CapabilityGrant,
    canonical_json,
    sha256_json,
    utc_now,
)


class ArtifactSigner:
    """HMAC signer used by the synthetic issuer and approval authority.

    Production key management is deliberately out of scope for v0.1. The interface is
    replaceable with asymmetric signing or workload identity in a later milestone.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("signing key must contain at least 32 bytes")
        self._key = key

    def sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(self._key, canonical_json(payload).encode(), hashlib.sha256).hexdigest()

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class CapabilityBroker:
    def __init__(self, signer: ArtifactSigner) -> None:
        self._signer = signer
        self._grants: dict[str, CapabilityGrant] = {}
        self._uses: dict[str, int] = {}
        self._revoked: set[str] = set()

    def issue(
        self,
        *,
        issuer_id: str,
        subject_id: str,
        mission_id: str,
        action: str,
        resource_patterns: tuple[str, ...],
        lifetime: timedelta = timedelta(minutes=5),
        max_uses: int = 1,
        requires_approval: bool = False,
        parameter_constraints: dict[str, tuple[Any, ...]] | None = None,
        now: datetime | None = None,
    ) -> CapabilityGrant:
        issued = now or utc_now()
        payload: dict[str, Any] = {
            "capability_id": f"CAP-{uuid.uuid4().hex[:16]}",
            "issuer_id": issuer_id,
            "subject_id": subject_id,
            "mission_id": mission_id,
            "action": action,
            "resource_patterns": resource_patterns,
            "parameter_constraints": parameter_constraints or {},
            "valid_from": issued,
            "expires_at": issued + lifetime,
            "max_uses": max_uses,
            "requires_approval": requires_approval,
            "delegable": False,
        }
        normalized = CapabilityGrant(**payload, signature="pending").unsigned_payload()
        grant = CapabilityGrant(**payload, signature=self._signer.sign(normalized))
        self._grants[grant.capability_id] = grant
        self._uses[grant.capability_id] = 0
        return grant

    @staticmethod
    def token_for(grant: CapabilityGrant) -> str:
        raw = canonical_json(grant.model_dump(mode="json")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @staticmethod
    def decode_token(token: str) -> CapabilityGrant | None:
        try:
            padded = token + "=" * (-len(token) % 4)
            data = json.loads(base64.urlsafe_b64decode(padded.encode()))
            return CapabilityGrant.model_validate(data)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    def validate(
        self, envelope: ActionEnvelope, *, now: datetime
    ) -> tuple[bool, str, CapabilityGrant | None]:
        grant = self.decode_token(envelope.capability_token)
        if grant is None:
            return False, "CAPABILITY_MALFORMED", None
        registered = self._grants.get(grant.capability_id)
        if registered is None:
            return False, "CAPABILITY_SELF_ISSUED", grant
        if registered != grant or not self._signer.verify(
            grant.unsigned_payload(), grant.signature
        ):
            return False, "CAPABILITY_TAMPERED", grant
        if grant.capability_id in self._revoked:
            return False, "CAPABILITY_REVOKED", grant
        if not (grant.valid_from <= now < grant.expires_at):
            return False, "CAPABILITY_EXPIRED", grant
        if self._uses[grant.capability_id] >= grant.max_uses:
            return False, "CAPABILITY_EXHAUSTED", grant
        if grant.subject_id != envelope.agent_id:
            return False, "CAPABILITY_WRONG_SUBJECT", grant
        if grant.mission_id != envelope.mission_id:
            return False, "CAPABILITY_WRONG_MISSION", grant
        if grant.action != envelope.action:
            return False, "CAPABILITY_WRONG_ACTION", grant
        if not any(fnmatchcase(envelope.resource, pattern) for pattern in grant.resource_patterns):
            return False, "CAPABILITY_RESOURCE_OUT_OF_SCOPE", grant
        for key, permitted in grant.parameter_constraints.items():
            if envelope.parameters.get(key) not in permitted:
                return False, "CAPABILITY_PARAMETER_OUT_OF_SCOPE", grant
        return True, "CAPABILITY_VALID", grant

    def consume(self, capability_id: str) -> None:
        if capability_id not in self._grants:
            raise KeyError("unknown capability")
        self._uses[capability_id] += 1

    def revoke(self, capability_id: str) -> None:
        self._revoked.add(capability_id)

    def inspect(self) -> list[dict[str, Any]]:
        return [
            {
                **grant.model_dump(mode="json"),
                "uses": self._uses[grant.capability_id],
                "revoked": grant.capability_id in self._revoked,
            }
            for grant in self._grants.values()
        ]


class ApprovalVerifier:
    def __init__(self, signer: ArtifactSigner) -> None:
        self._signer = signer
        self._issued: dict[str, ApprovalArtifact] = {}
        self._consumed: set[str] = set()

    def issue(
        self,
        envelope: ActionEnvelope,
        *,
        approver_identity: str,
        lifetime: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> ApprovalArtifact:
        issued = now or utc_now()
        payload: dict[str, Any] = {
            "approval_id": f"APR-{uuid.uuid4().hex[:16]}",
            "approver_identity": approver_identity,
            "request_hash": envelope.request_hash,
            "mission_id": envelope.mission_id,
            "action": envelope.action,
            "resource": envelope.resource,
            "parameters_hash": sha256_json(envelope.parameters),
            "issued_at": issued,
            "expires_at": issued + lifetime,
        }
        normalized = ApprovalArtifact(**payload, signature="pending").unsigned_payload()
        artifact = ApprovalArtifact(**payload, signature=self._signer.sign(normalized))
        self._issued[artifact.approval_id] = artifact
        return artifact

    def validate(
        self, artifact: ApprovalArtifact, envelope: ActionEnvelope, *, now: datetime
    ) -> tuple[bool, str]:
        known = self._issued.get(artifact.approval_id)
        if known is None:
            return False, "APPROVAL_FORGED"
        if known != artifact or not self._signer.verify(
            artifact.unsigned_payload(), artifact.signature
        ):
            return False, "APPROVAL_TAMPERED"
        if artifact.approval_id in self._consumed:
            return False, "APPROVAL_REPLAYED"
        if not (artifact.issued_at <= now < artifact.expires_at):
            return False, "APPROVAL_EXPIRED"
        if artifact.approver_identity != envelope.controller_id:
            return False, "APPROVAL_WRONG_CONTROLLER"
        if artifact.request_hash != envelope.request_hash:
            return False, "APPROVAL_REQUEST_MISMATCH"
        return True, "APPROVAL_VALID"

    def consume(self, approval_id: str) -> None:
        if approval_id not in self._issued:
            raise KeyError("unknown approval")
        self._consumed.add(approval_id)
