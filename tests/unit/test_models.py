from datetime import timedelta

import pytest
from pydantic import ValidationError

from cerberus_null.models import ActionEnvelope, RiskTier, utc_now


def test_envelope_is_immutable() -> None:
    now = utc_now()
    envelope = ActionEnvelope(
        request_id="REQ-immutable",
        agent_id="agent-001",
        controller_id="human-001",
        mission_id="MISSION-001",
        action="read_alert",
        resource="siem-lab-alert-001",
        parameters={},
        reason="read",
        capability_token="token",  # noqa: S106 - inert schema fixture
        claimed_risk_tier=RiskTier.T0,
        created_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    with pytest.raises(ValidationError):
        envelope.action = "disable_audit_logging"  # type: ignore[misc]


def test_request_hash_changes_with_parameters() -> None:
    now = utc_now()
    base = dict(
        request_id="REQ-hash",
        agent_id="agent-001",
        controller_id="human-001",
        mission_id="MISSION-001",
        action="modify_mock_firewall",
        resource="firewall-lab-edge",
        reason="change",
        capability_token="token",  # noqa: S106 - inert schema fixture
        claimed_risk_tier=RiskTier.T3,
        created_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    first = ActionEnvelope(**base, parameters={"rule": "allow-one"})
    second = ActionEnvelope(**base, parameters={"rule": "allow-all"})
    assert first.request_hash != second.request_hash


def test_extra_envelope_fields_are_rejected() -> None:
    now = utc_now()
    with pytest.raises(ValidationError):
        ActionEnvelope(
            request_id="REQ-extra",
            agent_id="agent-001",
            controller_id="human-001",
            mission_id="MISSION-001",
            action="read_alert",
            resource="siem-lab-alert-001",
            reason="read",
            capability_token="token",  # noqa: S106 - inert schema fixture
            claimed_risk_tier=RiskTier.T0,
            created_at=now,
            expires_at=now + timedelta(minutes=1),
            hidden_authority=True,
        )
