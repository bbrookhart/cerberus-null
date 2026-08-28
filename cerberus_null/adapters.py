"""Narrow mock adapters. No shell, network, or production-system interface exists."""

from __future__ import annotations

from typing import Any

from cerberus_null.models import ActionSpec

_GATEWAY_PERMIT = object()


class MockEnvironment:
    def __init__(self) -> None:
        self.resources: dict[str, dict[str, Any]] = {
            "siem-lab-alert-001": {"status": "open", "severity": "medium"},
            "endpoint-lab-001": {"isolated": False, "healthy": True},
            "identity-lab-alice": {"disabled": False, "role": "analyst"},
            "firewall-lab-edge": {"rules": []},
            "cloud-lab-policy": {"policy": "baseline"},
            "application-lab-api": {"running": True},
            "ticket-lab-case": {"notes": []},
            "ot-lab-controller": {"setpoint": 50, "safety_enabled": True, "actuator": 0},
        }

    def snapshot(self, resource: str) -> dict[str, Any]:
        return dict(self.resources.setdefault(resource, {}))


class ProtectedAdapter:
    def __init__(self, name: str, environment: MockEnvironment) -> None:
        self.name = name
        self._environment = environment

    def execute(
        self,
        spec: ActionSpec,
        resource: str,
        parameters: dict[str, Any],
        *,
        permit: object | None = None,
    ) -> dict[str, Any]:
        if permit is not _GATEWAY_PERMIT:
            raise PermissionError("protected adapters are reachable only through ExecutionGateway")
        state = self._environment.resources.setdefault(resource, {})
        before = dict(state)

        if spec.risk_tier.value == 0:
            return {"adapter": self.name, "resource": resource, "observed": before}
        if spec.name == "create_ticket":
            state.update({"title": parameters["title"], "status": "open"})
        elif spec.name == "add_case_note":
            state.setdefault("notes", []).append(parameters["note"])
        elif spec.name in {"request_additional_telemetry", "increase_mock_logging"}:
            state["telemetry"] = "increased"
        elif spec.name == "isolate_mock_endpoint":
            state["isolated"] = True
        elif spec.name == "expire_mock_session":
            state["session"] = "expired"
        elif spec.name == "disable_mock_account":
            state["disabled"] = True
        elif spec.name == "block_mock_indicator":
            state["indicator_blocked"] = True
        elif spec.name == "restart_mock_service":
            state["restart_count"] = int(state.get("restart_count", 0)) + 1
            state["running"] = True
        elif spec.name == "modify_mock_firewall":
            state.setdefault("rules", []).append(parameters["rule"])
        elif spec.name == "change_mock_identity_role":
            state["role"] = parameters["role"]
        elif spec.name == "modify_mock_cloud_security_policy":
            state["policy"] = parameters["policy"]
        elif spec.name == "disable_mock_critical_service":
            state["running"] = False
        else:
            raise RuntimeError("registered action has no mock implementation")
        return {"adapter": self.name, "resource": resource, "before": before, "after": dict(state)}


class AdapterRegistry:
    def __init__(self, environment: MockEnvironment) -> None:
        self._adapters = {
            name: ProtectedAdapter(name, environment)
            for name in (
                "siem",
                "identity",
                "endpoint",
                "firewall",
                "cloud",
                "ot",
                "ticket",
                "application",
            )
        }

    def execute(
        self, spec: ActionSpec, resource: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        adapter = self._adapters.get(spec.adapter)
        if adapter is None:
            raise RuntimeError("no executable adapter registered")
        return adapter.execute(spec, resource, parameters, permit=_GATEWAY_PERMIT)

    def adapter_for_test(self, name: str) -> ProtectedAdapter:
        """Architecture tests use this to demonstrate direct invocation fails closed."""
        return self._adapters[name]
