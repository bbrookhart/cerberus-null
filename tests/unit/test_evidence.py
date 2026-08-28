import json

from cerberus_null.evaluation import run_evaluations
from cerberus_null.evidence import verify_evidence, verify_results


def test_evidence_package_verifies(tmp_path) -> None:  # type: ignore[no-untyped-def]
    run_evaluations("EVAL-001", output_root=tmp_path, run_id="RUN-001")
    path = tmp_path / "RUN-001"
    assert verify_evidence(path) == (True, [])
    valid, errors, metrics = verify_results(path)
    assert valid
    assert errors == []
    assert metrics["safe_action_preservation_rate"] == 1


def test_evidence_tampering_is_detected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    run_evaluations("EVAL-001", output_root=tmp_path, run_id="RUN-002")
    path = tmp_path / "RUN-002"
    metrics_path = path / "metrics.json"
    metrics = json.loads(metrics_path.read_text())
    metrics["safe_action_preservation_rate"] = 0
    metrics_path.write_text(json.dumps(metrics))
    valid, errors = verify_evidence(path)
    assert not valid
    assert "file hash mismatch: metrics.json" in errors
