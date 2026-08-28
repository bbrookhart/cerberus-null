import pytest
from conftest import make_envelope, provenance
from hypothesis import given, settings
from hypothesis import strategies as st

from cerberus_null.models import (
    Decision,
    IdentityKind,
    RiskTier,
    utc_now,
)
from cerberus_null.runtime import build_runtime


@pytest.mark.property
@given(
    st.sampled_from(
        [
            "modify_mock_ot_setpoint",
            "disable_mock_safety_control",
            "bypass_security_kernel",
            "disable_audit_logging",
            "modify_authorization_policy",
        ]
    )
)
@settings(max_examples=30)
def test_inv_ot_prohibited_actions_never_execute(action: str) -> None:
    runtime = build_runtime()
    parameters = {"setpoint": 50} if action == "modify_mock_ot_setpoint" else {}
    resource = "ot-lab-controller" if "ot_" in action or "safety" in action else "control-kernel"
    envelope = make_envelope(runtime, action=action, resource=resource, parameters=parameters)
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert result.decision is Decision.NULL
    assert not result.executed


@pytest.mark.property
@given(
    st.text(min_size=1, max_size=30).filter(lambda value: not value.startswith("siem-lab-alert-"))
)
@settings(max_examples=50)
def test_inv_auth_out_of_scope_resource_never_executes(resource: str) -> None:
    runtime = build_runtime()
    envelope = make_envelope(runtime, resource=resource, capability_resource="siem-lab-alert-*")
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert not result.executed


@pytest.mark.property
@given(st.sampled_from([RiskTier.T1, RiskTier.T2, RiskTier.T3, RiskTier.T4]))
def test_inv_tier_claim_cannot_expand_authority(claimed: RiskTier) -> None:
    runtime = build_runtime()
    envelope = make_envelope(runtime).model_copy(update={"claimed_risk_tier": claimed})
    result = runtime.gateway.process(envelope, provenance=provenance(), now=utc_now())
    assert not result.executed


@pytest.mark.property
@given(st.sampled_from(["isolate_mock_endpoint", "disable_mock_account", "restart_mock_service"]))
def test_inv_stop_blocks_every_consequential_action(action: str) -> None:
    runtime = build_runtime()
    resource = {
        "isolate_mock_endpoint": "endpoint-lab-001",
        "disable_mock_account": "identity-lab-alice",
        "restart_mock_service": "application-lab-api",
    }[action]
    operator = runtime.identities.resolve("human-operator-01", IdentityKind.HUMAN)
    assert operator is not None
    runtime.emergency_stop.engage(operator)
    result = runtime.gateway.process(
        make_envelope(runtime, action=action, resource=resource),
        provenance=provenance(),
        now=utc_now(),
    )
    assert result.decision is Decision.NULL
    assert not result.executed
