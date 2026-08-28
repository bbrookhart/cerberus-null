"""Deterministic, deny-by-default authorization decision point."""

from __future__ import annotations

import time
from datetime import datetime
from fnmatch import fnmatchcase

from cerberus_null.authority import ApprovalVerifier, CapabilityBroker
from cerberus_null.models import (
    ActionEnvelope,
    ApprovalArtifact,
    AuthorizationResult,
    CheckResult,
    Decision,
    IdentityKind,
    ProvenanceLabel,
    ProvenanceRecord,
    RiskTier,
    sha256_json,
)
from cerberus_null.registry import ACTION_REGISTRY, get_action_spec
from cerberus_null.state import EmergencyStop, IdentityResolver, MissionRegistry, PolicyHealth


class PolicyDecisionPoint:
    """The trusted kernel. Identical immutable inputs produce identical decisions."""

    def __init__(
        self,
        *,
        identities: IdentityResolver,
        missions: MissionRegistry,
        capabilities: CapabilityBroker,
        approvals: ApprovalVerifier,
        emergency_stop: EmergencyStop,
        policy_health: PolicyHealth,
    ) -> None:
        self._identities = identities
        self._missions = missions
        self._capabilities = capabilities
        self._approvals = approvals
        self._emergency_stop = emergency_stop
        self._policy_health = policy_health
        self.policy_version = "cerberus-null-policy-v0.1.0"
        self.policy_hash = sha256_json(
            {
                "version": self.policy_version,
                "default": Decision.NULL,
                "actions": {
                    name: {
                        **spec.model_dump(mode="json", exclude={"parameter_schema"}),
                        "parameter_schema": {
                            key: expected.__name__
                            for key, expected in sorted(spec.parameter_schema.items())
                        },
                    }
                    for name, spec in sorted(ACTION_REGISTRY.items())
                },
            }
        )

    def decide(
        self,
        envelope: ActionEnvelope,
        *,
        provenance: tuple[ProvenanceRecord, ...],
        approval: ApprovalArtifact | None,
        now: datetime,
    ) -> AuthorizationResult:
        started = time.perf_counter_ns()
        checks: list[CheckResult] = []

        def finish(decision: Decision, reason: str) -> AuthorizationResult:
            spec = get_action_spec(envelope.action)
            return AuthorizationResult(
                request_id=envelope.request_id,
                decision=decision,
                reason_code=reason,
                checks=tuple(checks),
                action_tier=spec.risk_tier if spec else None,
                blast_radius=spec.blast_radius if spec else None,
                policy_version=self.policy_version,
                policy_hash=self.policy_hash,
                latency_ms=(time.perf_counter_ns() - started) / 1_000_000,
            )

        if not self._policy_health.healthy:
            checks.append(CheckResult(control="policy_health", passed=False, detail="unavailable"))
            return finish(Decision.NULL, "POLICY_STATE_UNTRUSTED")
        checks.append(CheckResult(control="policy_health", passed=True, detail="healthy"))

        spec = get_action_spec(envelope.action)
        if spec is None:
            checks.append(
                CheckResult(control="action_registry", passed=False, detail="unknown action")
            )
            return finish(Decision.NULL, "UNKNOWN_TOOL")
        checks.append(CheckResult(control="action_registry", passed=True, detail=spec.name))

        if envelope.claimed_risk_tier is not spec.risk_tier:
            checks.append(
                CheckResult(control="tier_integrity", passed=False, detail="claim mismatch")
            )
            return finish(Decision.NULL, "RISK_TIER_MISMATCH")
        checks.append(
            CheckResult(control="tier_integrity", passed=True, detail=spec.risk_tier.label)
        )

        if not spec.validate_parameters(envelope.parameters):
            checks.append(
                CheckResult(control="parameter_schema", passed=False, detail="invalid shape")
            )
            return finish(Decision.NULL, "MALFORMED_PARAMETERS")
        checks.append(CheckResult(control="parameter_schema", passed=True, detail="valid"))

        if envelope.created_at > now or now >= envelope.expires_at:
            checks.append(
                CheckResult(control="request_freshness", passed=False, detail="expired or future")
            )
            return finish(Decision.NULL, "REQUEST_EXPIRED")
        checks.append(CheckResult(control="request_freshness", passed=True, detail="fresh"))

        agent = self._identities.resolve(envelope.agent_id, IdentityKind.AGENT)
        controller = self._identities.resolve(envelope.controller_id, IdentityKind.HUMAN)
        if agent is None or controller is None:
            checks.append(
                CheckResult(control="identity", passed=False, detail="ambiguous or inactive")
            )
            return finish(Decision.NULL, "IDENTITY_UNRESOLVED")
        checks.append(
            CheckResult(control="identity", passed=True, detail="agent and controller active")
        )

        if self._emergency_stop.engaged and spec.risk_tier > RiskTier.T0:
            checks.append(CheckResult(control="emergency_stop", passed=False, detail="engaged"))
            return finish(Decision.NULL, "EMERGENCY_STOP_ACTIVE")
        checks.append(
            CheckResult(control="emergency_stop", passed=True, detail="clear or observation")
        )

        if not spec.autonomous_execution or spec.risk_tier is RiskTier.T4:
            checks.append(
                CheckResult(control="autonomy_boundary", passed=False, detail="T4 prohibited")
            )
            return finish(Decision.NULL, "PROHIBITED_AUTONOMOUS_ACTION")
        checks.append(
            CheckResult(control="autonomy_boundary", passed=True, detail="within v0.1 boundary")
        )

        mission = self._missions.get(envelope.mission_id)
        if mission is None:
            checks.append(CheckResult(control="mission", passed=False, detail="unknown"))
            return finish(Decision.DENY, "MISSION_UNKNOWN")
        mission_valid = (
            mission.agent_id == envelope.agent_id
            and mission.controller_id == envelope.controller_id
            and mission.valid_from <= now < mission.expires_at
            and spec.risk_tier <= mission.maximum_action_tier
            and any(
                fnmatchcase(envelope.resource, pattern) for pattern in mission.allowed_resources
            )
        )
        if not mission_valid:
            checks.append(
                CheckResult(control="mission", passed=False, detail="outside delegated mission")
            )
            return finish(Decision.DENY, "MISSION_SCOPE_VIOLATION")
        checks.append(CheckResult(control="mission", passed=True, detail=mission.mission_id))

        if spec.risk_tier >= RiskTier.T2 and (
            not provenance or any(item.label is ProvenanceLabel.UNKNOWN for item in provenance)
        ):
            checks.append(
                CheckResult(control="provenance", passed=False, detail="unknown or absent")
            )
            return finish(Decision.NULL, "PROVENANCE_UNRESOLVED")
        checks.append(
            CheckResult(
                control="provenance",
                passed=True,
                detail="labels do not establish authority",
            )
        )

        valid_capability, cap_reason, capability = self._capabilities.validate(envelope, now=now)
        if not valid_capability or capability is None:
            checks.append(CheckResult(control="capability", passed=False, detail=cap_reason))
            return finish(Decision.DENY, cap_reason)
        checks.append(
            CheckResult(control="capability", passed=True, detail=capability.capability_id)
        )

        approval_required = spec.approval_required or capability.requires_approval
        if approval_required and approval is None:
            checks.append(CheckResult(control="approval", passed=False, detail="required"))
            return finish(Decision.REQUIRE_APPROVAL, "HUMAN_APPROVAL_REQUIRED")
        if approval_required and approval is not None:
            valid_approval, approval_reason = self._approvals.validate(approval, envelope, now=now)
            if not valid_approval:
                checks.append(CheckResult(control="approval", passed=False, detail=approval_reason))
                return finish(Decision.DENY, approval_reason)
            checks.append(CheckResult(control="approval", passed=True, detail=approval.approval_id))
        else:
            checks.append(CheckResult(control="approval", passed=True, detail="not required"))

        checks.append(CheckResult(control="safety_invariants", passed=True, detail="all evaluated"))
        return finish(Decision.ALLOW, "AUTHORIZED")
