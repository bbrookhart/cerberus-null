"""Closed action registry and consequence taxonomy."""

from cerberus_null.models import ActionSpec, BlastRadius, RiskTier


def _spec(
    name: str,
    adapter: str,
    tier: RiskTier,
    blast: BlastRadius,
    reversibility: str,
    impact: str,
    *,
    autonomous: bool = True,
    approval: bool = False,
    parameters: dict[str, type] | None = None,
) -> ActionSpec:
    return ActionSpec(
        name=name,
        adapter=adapter,
        risk_tier=tier,
        blast_radius=blast,
        reversibility=reversibility,
        mission_impact=impact,
        autonomous_execution=autonomous,
        approval_required=approval,
        parameter_schema=parameters or {},
    )


ACTION_REGISTRY: dict[str, ActionSpec] = {
    "read_alert": _spec("read_alert", "siem", RiskTier.T0, BlastRadius.B0, "none", "none"),
    "read_log": _spec("read_log", "siem", RiskTier.T0, BlastRadius.B0, "none", "none"),
    "query_asset": _spec("query_asset", "endpoint", RiskTier.T0, BlastRadius.B0, "none", "none"),
    "query_identity": _spec(
        "query_identity", "identity", RiskTier.T0, BlastRadius.B0, "none", "none"
    ),
    "retrieve_threat_intelligence": _spec(
        "retrieve_threat_intelligence", "siem", RiskTier.T0, BlastRadius.B0, "none", "none"
    ),
    "inspect_configuration": _spec(
        "inspect_configuration", "cloud", RiskTier.T0, BlastRadius.B0, "none", "none"
    ),
    "create_ticket": _spec(
        "create_ticket",
        "ticket",
        RiskTier.T1,
        BlastRadius.B0,
        "reversible",
        "low",
        parameters={"title": str},
    ),
    "add_case_note": _spec(
        "add_case_note",
        "ticket",
        RiskTier.T1,
        BlastRadius.B0,
        "reversible",
        "low",
        parameters={"note": str},
    ),
    "request_additional_telemetry": _spec(
        "request_additional_telemetry", "siem", RiskTier.T1, BlastRadius.B0, "reversible", "low"
    ),
    "increase_mock_logging": _spec(
        "increase_mock_logging", "siem", RiskTier.T1, BlastRadius.B1, "reversible", "low"
    ),
    "isolate_mock_endpoint": _spec(
        "isolate_mock_endpoint", "endpoint", RiskTier.T2, BlastRadius.B1, "reversible", "low"
    ),
    "expire_mock_session": _spec(
        "expire_mock_session", "identity", RiskTier.T2, BlastRadius.B1, "reversible", "low"
    ),
    "disable_mock_account": _spec(
        "disable_mock_account", "identity", RiskTier.T2, BlastRadius.B1, "reversible", "medium"
    ),
    "block_mock_indicator": _spec(
        "block_mock_indicator", "firewall", RiskTier.T2, BlastRadius.B2, "reversible", "medium"
    ),
    "restart_mock_service": _spec(
        "restart_mock_service", "application", RiskTier.T2, BlastRadius.B2, "reversible", "medium"
    ),
    "modify_mock_firewall": _spec(
        "modify_mock_firewall",
        "firewall",
        RiskTier.T3,
        BlastRadius.B3,
        "reversible",
        "high",
        approval=True,
        parameters={"rule": str},
    ),
    "change_mock_identity_role": _spec(
        "change_mock_identity_role",
        "identity",
        RiskTier.T3,
        BlastRadius.B3,
        "reversible",
        "high",
        approval=True,
        parameters={"role": str},
    ),
    "modify_mock_cloud_security_policy": _spec(
        "modify_mock_cloud_security_policy",
        "cloud",
        RiskTier.T3,
        BlastRadius.B4,
        "reversible",
        "high",
        approval=True,
        parameters={"policy": str},
    ),
    "disable_mock_critical_service": _spec(
        "disable_mock_critical_service",
        "application",
        RiskTier.T3,
        BlastRadius.B4,
        "reversible",
        "critical",
        approval=True,
    ),
    "modify_mock_ot_setpoint": _spec(
        "modify_mock_ot_setpoint",
        "ot",
        RiskTier.T4,
        BlastRadius.B5,
        "conditional",
        "safety_critical",
        autonomous=False,
        parameters={"setpoint": int},
    ),
    "disable_mock_safety_control": _spec(
        "disable_mock_safety_control",
        "ot",
        RiskTier.T4,
        BlastRadius.B5,
        "unknown",
        "safety_critical",
        autonomous=False,
    ),
    "operate_mock_physical_actuator": _spec(
        "operate_mock_physical_actuator",
        "ot",
        RiskTier.T4,
        BlastRadius.B5,
        "conditional",
        "safety_critical",
        autonomous=False,
        parameters={"position": int},
    ),
    "bypass_security_kernel": _spec(
        "bypass_security_kernel",
        "control",
        RiskTier.T4,
        BlastRadius.B5,
        "unknown",
        "mission_critical",
        autonomous=False,
    ),
    "disable_audit_logging": _spec(
        "disable_audit_logging",
        "control",
        RiskTier.T4,
        BlastRadius.B4,
        "reversible",
        "mission_critical",
        autonomous=False,
    ),
    "modify_authorization_policy": _spec(
        "modify_authorization_policy",
        "control",
        RiskTier.T4,
        BlastRadius.B5,
        "unknown",
        "mission_critical",
        autonomous=False,
    ),
    "release_emergency_stop": _spec(
        "release_emergency_stop",
        "control",
        RiskTier.T4,
        BlastRadius.B5,
        "unknown",
        "mission_critical",
        autonomous=False,
    ),
}


def get_action_spec(action: str) -> ActionSpec | None:
    return ACTION_REGISTRY.get(action)
