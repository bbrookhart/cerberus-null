from datetime import timedelta

import pytest
from conftest import make_envelope, provenance

from cerberus_null.authority import ArtifactSigner, CapabilityBroker
from cerberus_null.models import Decision, utc_now
from cerberus_null.registry import get_action_spec


@pytest.mark.parametrize(
    ("action", "resource", "parameters", "expected_key"),
    [
        ("read_alert", "siem-lab-alert-001", {}, "observed"),
        ("create_ticket", "ticket-lab-case", {"title": "case"}, "after"),
        ("add_case_note", "ticket-lab-case", {"note": "note"}, "after"),
        ("request_additional_telemetry", "siem-lab-alert-001", {}, "after"),
        ("increase_mock_logging", "siem-lab-alert-001", {}, "after"),
        ("isolate_mock_endpoint", "endpoint-lab-001", {}, "after"),
        ("expire_mock_session", "identity-lab-alice", {}, "after"),
        ("disable_mock_account", "identity-lab-alice", {}, "after"),
        ("block_mock_indicator", "firewall-lab-edge", {}, "after"),
        ("restart_mock_service", "application-lab-api", {}, "after"),
        ("modify_mock_firewall", "firewall-lab-edge", {"rule": "deny"}, "after"),
        ("change_mock_identity_role", "identity-lab-alice", {"role": "admin"}, "after"),
        (
            "modify_mock_cloud_security_policy",
            "cloud-lab-policy",
            {"policy": "strict"},
            "after",
        ),
        ("disable_mock_critical_service", "application-lab-api", {}, "after"),
    ],
)
def test_mock_adapter_operations_are_deterministic(
    runtime, action: str, resource: str, parameters: dict[str, object], expected_key: str
) -> None:  # type: ignore[no-untyped-def]
    spec = get_action_spec(action)
    assert spec is not None
    change = runtime.adapters.execute(spec, resource, parameters)
    assert change["resource"] == resource
    assert expected_key in change


def test_malformed_capability_fails_closed(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime).model_copy(update={"capability_token": "not-a-token"})
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "CAPABILITY_MALFORMED"
    assert not result.executed


def test_external_agent_cannot_self_issue(runtime) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(PermissionError):
        runtime.capabilities.issue(
            issuer_id="agent-investigator-01",
            subject_id="agent-investigator-01",
            mission_id="MISSION-001",
            action="read_alert",
            resource_patterns=("siem-lab-*",),
        )

    rogue = CapabilityBroker(
        ArtifactSigner(b"r" * 32),
        authorized_issuers=frozenset({"agent-investigator-01"}),
    )
    grant = rogue.issue(
        issuer_id="agent-investigator-01",
        subject_id="agent-investigator-01",
        mission_id="MISSION-001",
        action="read_alert",
        resource_patterns=("siem-lab-*",),
    )
    envelope = make_envelope(runtime).model_copy(
        update={"capability_token": CapabilityBroker.token_for(grant)}
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "CAPABILITY_SELF_ISSUED"


def test_capability_wrong_subject_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    now = utc_now()
    grant = runtime.capabilities.issue(
        issuer_id="human-operator-01",
        subject_id="agent-other",
        mission_id="MISSION-001",
        action="read_alert",
        resource_patterns=("siem-lab-*",),
        now=now - timedelta(seconds=1),
    )
    envelope = make_envelope(runtime).model_copy(
        update={"capability_token": CapabilityBroker.token_for(grant)}
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=now)
    assert result.reason_code == "CAPABILITY_WRONG_SUBJECT"


def test_unknown_identity_returns_null(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime).model_copy(update={"agent_id": "agent-unknown"})
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.NULL
    assert result.reason_code == "IDENTITY_UNRESOLVED"


def test_unknown_mission_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime).model_copy(update={"mission_id": "MISSION-UNKNOWN"})
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "MISSION_UNKNOWN"


def test_future_request_returns_null(runtime) -> None:  # type: ignore[no-untyped-def]
    future = utc_now() + timedelta(minutes=10)
    envelope = make_envelope(runtime).model_copy(
        update={"created_at": future, "expires_at": future + timedelta(minutes=1)}
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "REQUEST_EXPIRED"


def test_mission_autonomy_ceiling_is_enforced(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="modify_mock_firewall",
        resource="firewall-lab-edge",
        parameters={"rule": "allow-any"},
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "MISSION_SCOPE_VIOLATION"
    assert not result.executed


def test_missing_required_approval_is_pending(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="isolate_mock_endpoint",
        resource="endpoint-lab-001",
        requires_approval=True,
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert not result.executed


def test_forged_approval_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="isolate_mock_endpoint",
        resource="endpoint-lab-001",
        requires_approval=True,
    )
    approval = runtime.approvals.issue(envelope, approver_identity="human-operator-01")
    forged = approval.model_copy(update={"approval_id": "APR-forged"})
    result = runtime.gateway.process(
        envelope, provenance=provenance(), approval=forged, now=utc_now()
    )
    assert result.reason_code == "APPROVAL_FORGED"


def test_decision_records_policy_identity_and_audit(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime)
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert len(result.authorization.policy_hash) == 64
    assert result.authorization.policy_version == "cerberus-null-policy-v0.1.0"
    assert runtime.gateway.audit_log[-1]["request_hash"] == envelope.request_hash
    assert runtime.gateway.audit_log[-1]["decision"] is Decision.ALLOW


def test_policy_decision_is_deterministic_except_latency(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime, max_uses=2)
    first = runtime.policy.decide(
        envelope, provenance=provenance(), approval=None, now=envelope.created_at
    )
    second = runtime.policy.decide(
        envelope, provenance=provenance(), approval=None, now=envelope.created_at
    )
    assert first.model_dump(exclude={"latency_ms"}) == second.model_dump(exclude={"latency_ms"})
