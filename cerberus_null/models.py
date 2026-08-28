"""Strongly typed domain models shared by the trusted control plane."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


def canonical_json(value: Any) -> str:
    """Return a stable JSON representation suitable for hashing and signing."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    NULL = "NULL"


class RiskTier(IntEnum):
    T0 = 0
    T1 = 1
    T2 = 2
    T3 = 3
    T4 = 4

    @property
    def label(self) -> str:
        return self.name


class BlastRadius(IntEnum):
    B0 = 0
    B1 = 1
    B2 = 2
    B3 = 3
    B4 = 4
    B5 = 5

    @property
    def label(self) -> str:
        return self.name


class AutonomyLevel(IntEnum):
    A0 = 0
    A1 = 1
    A2 = 2
    A3 = 3
    A4 = 4
    A5 = 5


class ProvenanceLabel(StrEnum):
    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    TRUSTED_OPERATOR = "TRUSTED_OPERATOR"
    INTERNAL_VERIFIED = "INTERNAL_VERIFIED"
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"
    MODEL_GENERATED = "MODEL_GENERATED"
    UNKNOWN = "UNKNOWN"


class IdentityKind(StrEnum):
    AGENT = "AGENT"
    HUMAN = "HUMAN"
    SERVICE = "SERVICE"


class Identity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity_id: str = Field(min_length=3, max_length=128)
    kind: IdentityKind
    active: bool = True


class Mission(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    mission_id: str = Field(min_length=3, max_length=128)
    objective: str = Field(min_length=3, max_length=1000)
    agent_id: str
    controller_id: str
    allowed_resources: tuple[str, ...]
    maximum_action_tier: RiskTier
    autonomy_level: AutonomyLevel
    valid_from: datetime
    expires_at: datetime

    @field_validator("valid_from", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return value


class ActionEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    request_id: str = Field(min_length=3, max_length=128)
    agent_id: str = Field(min_length=3, max_length=128)
    controller_id: str = Field(min_length=3, max_length=128)
    mission_id: str = Field(min_length=3, max_length=128)
    action: str = Field(min_length=2, max_length=128, pattern=r"^[a-z][a-z0-9_]*$")
    resource: str = Field(min_length=1, max_length=256)
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=2000)
    evidence_refs: tuple[str, ...] = ()
    capability_token: str = Field(min_length=1)
    claimed_risk_tier: RiskTier
    created_at: datetime
    expires_at: datetime

    @field_validator("created_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return value

    def approval_binding(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "controller_id": self.controller_id,
            "mission_id": self.mission_id,
            "action": self.action,
            "resource": self.resource,
            "parameters_hash": sha256_json(self.parameters),
        }

    @property
    def request_hash(self) -> str:
        return sha256_json(self.approval_binding())


class ProvenanceRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source_id: str
    label: ProvenanceLabel
    content_hash: str
    observed_at: datetime
    parent_refs: tuple[str, ...] = ()


class CapabilityGrant(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    capability_id: str
    issuer_id: str
    subject_id: str
    mission_id: str
    action: str
    resource_patterns: tuple[str, ...]
    parameter_constraints: dict[str, tuple[Any, ...]] = Field(default_factory=dict)
    valid_from: datetime
    expires_at: datetime
    max_uses: int = Field(ge=1, le=10000)
    requires_approval: bool = False
    delegable: bool = False
    signature: str

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})


class ApprovalArtifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    approval_id: str
    approver_identity: str
    request_hash: str
    mission_id: str
    action: str
    resource: str
    parameters_hash: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})


class ActionSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str
    adapter: str
    risk_tier: RiskTier
    blast_radius: BlastRadius
    reversibility: str
    mission_impact: str
    autonomous_execution: bool
    approval_required: bool = False
    parameter_schema: dict[str, type] = Field(default_factory=dict)

    def validate_parameters(self, parameters: dict[str, Any]) -> bool:
        if set(parameters) != set(self.parameter_schema):
            return False
        return all(
            isinstance(parameters[key], expected) for key, expected in self.parameter_schema.items()
        )


class CheckResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    control: str
    passed: bool
    detail: str


class AuthorizationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    request_id: str
    decision: Decision
    reason_code: str
    checks: tuple[CheckResult, ...]
    action_tier: RiskTier | None
    blast_radius: BlastRadius | None
    policy_version: str
    policy_hash: str
    latency_ms: float


class ExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    request_id: str
    decision: Decision
    executed: bool
    reason_code: str
    environment_change: dict[str, Any] | None = None
    authorization: AuthorizationResult
    audit_complete: bool
