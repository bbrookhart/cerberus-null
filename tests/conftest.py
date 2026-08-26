from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from cerberus_null.authority import CapabilityBroker
from cerberus_null.models import (
    ActionEnvelope,
    ProvenanceLabel,
    ProvenanceRecord,
    RiskTier,
    sha256_json,
    utc_now,
)
from cerberus_null.registry import get_action_spec
from cerberus_null.runtime import Runtime, build_runtime


@pytest.fixture
def runtime() -> Runtime:
    return build_runtime()


def make_envelope(
    runtime: Runtime,
    *,
    action: str = "read_alert",
    resource: str = "siem-alert-001",
    parameters: dict[str, Any] | None = None,
    capability_action: str | None = None,
    capability_resource: str | None = None,
    requires_approval: bool = False,
    max_uses: int = 1,
) -> ActionEnvelope:
    now = utc_now()
    grant = runtime.capabilities.issue(
        issuer_id="human-operator-01",
        subject_id="agent-investigator-01",
        mission_id="MISSION-001",
        action=capability_action or action,
        resource_patterns=(capability_resource or resource,),
        requires_approval=requires_approval,
        max_uses=max_uses,
        now=now - timedelta(seconds=1),
    )
    spec = get_action_spec(action)
    return ActionEnvelope(
        request_id="REQ-test-001",
        agent_id="agent-investigator-01",
        controller_id="human-operator-01",
        mission_id="MISSION-001",
        action=action,
        resource=resource,
        parameters=parameters or {},
        reason="test request",
        capability_token=CapabilityBroker.token_for(grant),
        claimed_risk_tier=spec.risk_tier if spec else RiskTier.T3,
        created_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=1),
    )


def provenance(
    label: ProvenanceLabel = ProvenanceLabel.TRUSTED_SYSTEM,
) -> tuple[ProvenanceRecord, ...]:
    return (
        ProvenanceRecord(
            source_id="test-fixture",
            label=label,
            content_hash=sha256_json("fixture"),
            observed_at=utc_now(),
        ),
    )
