import pytest
from conftest import make_envelope, provenance

from cerberus_null.models import Decision, Identity, IdentityKind, utc_now


def test_stop_blocks_consequential_execution(runtime) -> None:  # type: ignore[no-untyped-def]
    operator = runtime.identities.resolve("human-operator-01", IdentityKind.HUMAN)
    assert operator is not None
    runtime.emergency_stop.engage(operator)
    envelope = make_envelope(runtime, action="isolate_mock_endpoint", resource="endpoint-lab-001")
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.NULL


def test_stop_preserves_observation(runtime) -> None:  # type: ignore[no-untyped-def]
    operator = runtime.identities.resolve("human-operator-01", IdentityKind.HUMAN)
    assert operator is not None
    runtime.emergency_stop.engage(operator)
    result = runtime.gateway.process(make_envelope(runtime), provenance=provenance(), now=utc_now())
    assert result.decision is Decision.ALLOW


def test_agent_cannot_release_stop(runtime) -> None:  # type: ignore[no-untyped-def]
    agent = Identity(identity_id="agent-hostile", kind=IdentityKind.AGENT)
    runtime.emergency_stop.engage(agent)
    with pytest.raises(PermissionError):
        runtime.emergency_stop.release(agent)
