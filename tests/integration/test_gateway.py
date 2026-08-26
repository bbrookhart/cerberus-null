from conftest import make_envelope, provenance

from cerberus_null.models import Decision, utc_now


def test_execution_mutates_only_mock_environment(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime, action="isolate_mock_endpoint", resource="endpoint-lab-001")
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.executed
    assert runtime.environment.snapshot("endpoint-lab-001")["isolated"] is True


def test_denied_request_does_not_mutate_environment(runtime) -> None:  # type: ignore[no-untyped-def]
    before = runtime.environment.snapshot("identity-lab-alice")
    envelope = make_envelope(
        runtime,
        action="disable_mock_account",
        resource="identity-lab-alice",
        capability_action="read_alert",
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.DENY
    assert runtime.environment.snapshot("identity-lab-alice") == before
