from conftest import make_envelope, provenance

from cerberus_null.models import Decision, ProvenanceLabel, RiskTier, utc_now


def test_unknown_tool_returns_null(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime).model_copy(
        update={"action": "unknown_tool", "claimed_risk_tier": RiskTier.T3}
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.NULL
    assert result.reason_code == "UNKNOWN_TOOL"


def test_tier_mismatch_returns_null(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime).model_copy(update={"claimed_risk_tier": RiskTier.T3})
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "RISK_TIER_MISMATCH"


def test_malformed_parameters_return_null(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="create_ticket",
        resource="ticket-lab-case",
        parameters={"unexpected": "value"},
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.reason_code == "MALFORMED_PARAMETERS"


def test_t4_action_has_no_executable_path(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(
        runtime,
        action="modify_mock_ot_setpoint",
        resource="ot-lab-controller",
        parameters={"setpoint": 80},
    )
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.NULL
    assert not result.executed


def test_unknown_provenance_returns_null_for_t2(runtime) -> None:  # type: ignore[no-untyped-def]
    envelope = make_envelope(runtime, action="isolate_mock_endpoint", resource="endpoint-lab-001")
    result = runtime.gateway.process(
        envelope,
        provenance=provenance(ProvenanceLabel.UNKNOWN),
        now=utc_now(),
    )
    assert result.reason_code == "PROVENANCE_UNRESOLVED"


def test_policy_failure_returns_null(runtime) -> None:  # type: ignore[no-untyped-def]
    runtime.policy_health.healthy = False
    result = runtime.gateway.process(make_envelope(runtime), provenance=provenance(), now=utc_now())
    assert result.decision is Decision.NULL
    assert result.reason_code == "POLICY_STATE_UNTRUSTED"
