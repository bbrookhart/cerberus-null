from datetime import timedelta

from conftest import make_envelope, provenance

from cerberus_null.models import Decision, utc_now


def test_t3_requires_exact_human_approval(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="modify_mock_firewall",
        resource="firewall-lab-edge",
        parameters={"rule": "deny-bad"},
        requires_approval=True,
    )
    pending = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert pending.decision is Decision.REQUIRE_APPROVAL
    approval = runtime.approvals.issue(envelope, approver_identity="human-operator-01")
    allowed = runtime.gateway.process(
        envelope, provenance=provenance(), approval=approval, now=utc_now()
    )
    assert allowed.decision is Decision.ALLOW
    assert allowed.executed


def test_request_change_invalidates_approval(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="modify_mock_firewall",
        resource="firewall-lab-edge",
        parameters={"rule": "deny-bad"},
        requires_approval=True,
    )
    approval = runtime.approvals.issue(envelope, approver_identity="human-operator-01")
    changed = envelope.model_copy(update={"parameters": {"rule": "allow-all"}})
    result = runtime.gateway.process(
        changed, provenance=provenance(), approval=approval, now=utc_now()
    )
    assert result.reason_code == "APPROVAL_REQUEST_MISMATCH"


def test_approval_replay_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="modify_mock_firewall",
        resource="firewall-lab-edge",
        parameters={"rule": "deny-bad"},
        requires_approval=True,
        max_uses=2,
    )
    approval = runtime.approvals.issue(envelope, approver_identity="human-operator-01")
    assert runtime.gateway.process(
        envelope, provenance=provenance(), approval=approval, now=utc_now()
    ).executed
    replay = envelope.model_copy(update={"request_id": envelope.request_id})
    result = runtime.gateway.process(
        replay, provenance=provenance(), approval=approval, now=utc_now()
    )
    assert result.reason_code == "APPROVAL_REPLAYED"


def test_expired_approval_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="modify_mock_firewall",
        resource="firewall-lab-edge",
        parameters={"rule": "deny-bad"},
        requires_approval=True,
    )
    approval = runtime.approvals.issue(
        envelope,
        approver_identity="human-operator-01",
        lifetime=timedelta(seconds=1),
        now=utc_now() - timedelta(minutes=1),
    )
    result = runtime.gateway.process(
        envelope, provenance=provenance(), approval=approval, now=utc_now()
    )
    assert result.reason_code == "APPROVAL_EXPIRED"
