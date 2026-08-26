from datetime import timedelta

from conftest import make_envelope, provenance

from cerberus_null.authority import CapabilityBroker
from cerberus_null.models import Decision, utc_now


def test_valid_capability_authorizes_safe_read(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime)
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.ALLOW
    assert result.executed


def test_wrong_action_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="disable_mock_account",
        resource="identity-lab-alice",
        capability_action="read_alert",
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.DENY
    assert result.reason_code == "CAPABILITY_WRONG_ACTION"


def test_wrong_resource_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime, capability_resource="siem-alert-other")
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "CAPABILITY_RESOURCE_OUT_OF_SCOPE"


def test_capability_is_single_use(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime)
    assert runtime.gateway.process(envelope, provenance=provenance(), now=utc_now()).executed
    replay = envelope.model_copy(update={"request_id": "REQ-test-002"})
    result = runtime.gateway.process(replay, provenance=provenance(), now=utc_now())
    assert result.reason_code == "CAPABILITY_EXHAUSTED"


def test_tampered_capability_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime)
    grant = runtime.capabilities.decode_token(envelope.capability_token)
    assert grant is not None
    tampered = grant.model_copy(update={"resource_patterns": ("*",)})
    envelope = envelope.model_copy(
        update={"capability_token": CapabilityBroker.token_for(tampered)}
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "CAPABILITY_TAMPERED"


def test_revoked_capability_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime)
    grant = runtime.capabilities.decode_token(envelope.capability_token)
    assert grant is not None
    runtime.capabilities.revoke(grant.capability_id)
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "CAPABILITY_REVOKED"


def test_expired_capability_is_denied(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime)
    result = runtime.gateway.process(
        envelope,
        provenance=provenance(),
        now=utc_now() + timedelta(minutes=10),
    )
    assert result.decision in {Decision.DENY, Decision.NULL}
