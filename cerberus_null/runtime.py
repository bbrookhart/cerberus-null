"""Composable local runtime used by the CLI, API, tests, and evaluation harness."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from cerberus_null.adapters import AdapterRegistry, MockEnvironment
from cerberus_null.authority import ApprovalVerifier, ArtifactSigner, CapabilityBroker
from cerberus_null.evidence import EvidenceRecorder
from cerberus_null.gateway import ExecutionGateway
from cerberus_null.models import AutonomyLevel, Identity, IdentityKind, Mission, RiskTier, utc_now
from cerberus_null.policy import PolicyDecisionPoint
from cerberus_null.state import EmergencyStop, IdentityResolver, MissionRegistry, PolicyHealth


@dataclass(frozen=True)
class Runtime:
    gateway: ExecutionGateway
    identities: IdentityResolver
    missions: MissionRegistry
    capabilities: CapabilityBroker
    approvals: ApprovalVerifier
    emergency_stop: EmergencyStop
    policy_health: PolicyHealth
    policy: PolicyDecisionPoint
    adapters: AdapterRegistry
    environment: MockEnvironment


def _local_key() -> bytes:
    configured = os.getenv("CERBERUS_SIGNING_KEY")
    if configured:
        return configured.encode()
    # Reproducible local TEVV key only. It is not a production credential.
    return hashlib.sha256(b"cerberus-null-v0.1-local-research-key").digest()


def build_runtime(
    *,
    evidence: EvidenceRecorder | None = None,
    state_file: Path | None = None,
) -> Runtime:
    now = utc_now()
    agent = Identity(identity_id="agent-investigator-01", kind=IdentityKind.AGENT)
    controller = Identity(identity_id="human-operator-01", kind=IdentityKind.HUMAN)
    identities = IdentityResolver((agent, controller))
    mission = Mission(
        mission_id="MISSION-001",
        objective="Investigate synthetic suspicious authentication activity.",
        agent_id=agent.identity_id,
        controller_id=controller.identity_id,
        allowed_resources=(
            "siem-lab-*",
            "endpoint-lab-*",
            "identity-lab-*",
        ),
        maximum_action_tier=RiskTier.T2,
        autonomy_level=AutonomyLevel.A2,
        valid_from=now - timedelta(days=1),
        expires_at=now + timedelta(days=1),
    )
    missions = MissionRegistry((mission,))
    signer = ArtifactSigner(_local_key())
    capabilities = CapabilityBroker(signer)
    approvals = ApprovalVerifier(signer)
    emergency_stop = EmergencyStop(state_file)
    policy_health = PolicyHealth()
    environment = MockEnvironment()
    adapters = AdapterRegistry(environment)
    policy = PolicyDecisionPoint(
        identities=identities,
        missions=missions,
        capabilities=capabilities,
        approvals=approvals,
        emergency_stop=emergency_stop,
        policy_health=policy_health,
    )
    gateway = ExecutionGateway(
        policy=policy,
        adapters=adapters,
        capabilities=capabilities,
        approvals=approvals,
        evidence=evidence,
    )
    return Runtime(
        gateway=gateway,
        identities=identities,
        missions=missions,
        capabilities=capabilities,
        approvals=approvals,
        emergency_stop=emergency_stop,
        policy_health=policy_health,
        policy=policy,
        adapters=adapters,
        environment=environment,
    )
