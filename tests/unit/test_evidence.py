import json

from cerberus_null.evidence import EvidenceRecorder, verify_evidence


def test_evidence_package_verifies(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recorder = EvidenceRecorder(tmp_path, "RUN-001")
    recorder.write_json("configuration.json", {"mode": "test"})
    recorder.append("decisions.jsonl", {"decision": "NULL"})
    path = recorder.finalize(metrics={"escape_rate": 0}, summary="# Summary")
    assert verify_evidence(path) == (True, [])


def test_evidence_tampering_is_detected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    recorder = EvidenceRecorder(tmp_path, "RUN-002")
    path = recorder.finalize(metrics={"escape_rate": 0}, summary="# Summary")
    metrics_path = path / "metrics.json"
    metrics_path.write_text(json.dumps({"escape_rate": 1}))
    valid, errors = verify_evidence(path)
    assert not valid
    assert "file hash mismatch: metrics.json" in errors
