import ast
from pathlib import Path

import pytest

from cerberus_null.models import RiskTier
from cerberus_null.registry import get_action_spec


@pytest.mark.architecture
def test_direct_adapter_invocation_fails(runtime) -> None:  # type: ignore[no-untyped-def]
    adapter = runtime.adapters.adapter_for_test("siem")
    spec = get_action_spec("read_alert")
    assert spec is not None
    with pytest.raises(PermissionError):
        adapter.execute(spec, "siem-lab-alert-001", {})


@pytest.mark.architecture
def test_agent_layer_does_not_import_gateway_or_adapters() -> None:
    source = Path("cerberus_null/agent.py").read_text()
    imported = {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "cerberus_null.gateway" not in imported
    assert "cerberus_null.adapters" not in imported


@pytest.mark.architecture
def test_no_generic_shell_execution_api_exists() -> None:
    prohibited = {"subprocess", "os.system", "execute_shell", "DockerClient"}
    for path in Path("cerberus_null").glob("*.py"):
        text = path.read_text()
        assert not any(term in text for term in prohibited), f"prohibited API in {path}"


@pytest.mark.architecture
def test_t4_registry_is_non_autonomous() -> None:
    from cerberus_null.registry import ACTION_REGISTRY

    assert all(
        not spec.autonomous_execution
        for spec in ACTION_REGISTRY.values()
        if spec.risk_tier is RiskTier.T4
    )
