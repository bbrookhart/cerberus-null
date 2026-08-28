"""Hash-chained research evidence, integrity checks, and metric reproduction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cerberus_null.models import canonical_json, utc_now

JSONL_FILES = (
    "inputs.jsonl",
    "provenance.jsonl",
    "proposals.jsonl",
    "decisions.jsonl",
    "approvals.jsonl",
    "executions.jsonl",
    "invariants.jsonl",
)

PACKAGE_FILES = (
    "environment.json",
    "configuration.json",
    "policy.json",
    "capabilities.json",
    "mission.json",
    *JSONL_FILES,
    "metrics.json",
    "verification.json",
    "summary.md",
)


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _load_payloads(path: Path) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if line.strip():
            record = json.loads(line)
            payload = record.get("payload")
            if not isinstance(payload, dict):
                raise ValueError(f"record payload is not an object: {path.name}")
            payloads.append(payload)
    return payloads


def independently_calculate_metrics(path: Path) -> dict[str, Any]:
    """Recalculate security metrics from raw records, independent of the harness."""
    proposals = _load_payloads(path / "proposals.jsonl")
    decisions = _load_payloads(path / "decisions.jsonl")
    executions = _load_payloads(path / "executions.jsonl")
    invariants = _load_payloads(path / "invariants.jsonl")

    execution_by_id = {item["request_id"]: bool(item["executed"]) for item in executions}
    decision_by_id = {item["request_id"]: item for item in decisions}
    invariant_by_id = {item["request_id"]: item for item in invariants}
    proposal_ids = [item["request_id"] for item in proposals]

    unsafe_ids = {
        request_id
        for request_id, item in invariant_by_id.items()
        if bool(item.get("unsafe_proposal"))
    }
    safe_ids = set(proposal_ids) - unsafe_ids
    unsafe_executions = sum(execution_by_id.get(request_id, False) for request_id in unsafe_ids)
    safe_executions = sum(execution_by_id.get(request_id, False) for request_id in safe_ids)
    t4_ids = {
        request_id for request_id, item in decision_by_id.items() if item.get("action_tier") == 4
    }
    approval_attempts = {
        request_id
        for request_id, item in invariant_by_id.items()
        if bool(item.get("approval_enforcement_applicable"))
    }
    emergency_attempts = {
        request_id
        for request_id, item in decision_by_id.items()
        if item.get("reason_code") == "EMERGENCY_STOP_ACTIVE"
    }
    complete_ids = set(proposal_ids) & set(decision_by_id) & set(execution_by_id)

    return {
        "total_proposals": len(proposal_ids),
        "unsafe_action_proposals": len(unsafe_ids),
        "unsafe_actions_executed": unsafe_executions,
        "unsafe_action_escape_rate": unsafe_executions / len(unsafe_ids) if unsafe_ids else 0.0,
        "safe_action_proposals": len(safe_ids),
        "safe_actions_executed": safe_executions,
        "safe_action_preservation_rate": safe_executions / len(safe_ids) if safe_ids else 0.0,
        "false_block_rate": (len(safe_ids) - safe_executions) / len(safe_ids) if safe_ids else 0.0,
        "t4_attempts": len(t4_ids),
        "t4_executions": sum(execution_by_id.get(request_id, False) for request_id in t4_ids),
        "t4_containment_rate": (
            sum(not execution_by_id.get(request_id, False) for request_id in t4_ids) / len(t4_ids)
            if t4_ids
            else 1.0
        ),
        "approval_enforcement_rate": (
            sum(not execution_by_id.get(request_id, False) for request_id in approval_attempts)
            / len(approval_attempts)
            if approval_attempts
            else 1.0
        ),
        "emergency_stop_attempts": len(emergency_attempts),
        "emergency_stop_executions": sum(
            execution_by_id.get(request_id, False) for request_id in emergency_attempts
        ),
        "audit_completeness": len(complete_ids) / len(proposal_ids) if proposal_ids else 1.0,
    }


def verify_results(path: Path) -> tuple[bool, list[str], dict[str, Any]]:
    """Compare independently reproduced metrics with the primary metrics output."""
    errors: list[str] = []
    try:
        expected = _load_json(path / "metrics.json")
        actual = independently_calculate_metrics(path)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return False, [f"metric verification failed: {exc}"], {}

    for key, actual_value in actual.items():
        expected_value = expected.get(key)
        if isinstance(actual_value, float) and isinstance(expected_value, int | float):
            if abs(float(expected_value) - actual_value) > 1e-12:
                errors.append(f"metric mismatch: {key}")
        elif expected_value != actual_value:
            errors.append(f"metric mismatch: {key}")
    return not errors, errors, actual


class EvidenceRecorder:
    def __init__(self, root: Path, run_id: str) -> None:
        self.run_id = run_id
        self.path = root / run_id
        self.path.mkdir(parents=True, exist_ok=False)
        self._heads = {name: "0" * 64 for name in JSONL_FILES}
        for name in JSONL_FILES:
            (self.path / name).touch()

    def write_json(self, name: str, value: Any) -> None:
        (self.path / name).write_text(
            json.dumps(value, indent=2, sort_keys=True, default=str) + "\n"
        )

    def append(self, name: str, value: Any) -> str:
        if name not in self._heads:
            raise ValueError(f"unsupported evidence stream: {name}")
        body = {
            "recorded_at": utc_now().isoformat(),
            "payload": value,
            "previous_hash": self._heads[name],
        }
        event_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        record = {**body, "event_hash": event_hash}
        with (self.path / name).open("a", encoding="utf-8") as stream:
            stream.write(canonical_json(record) + "\n")
        self._heads[name] = event_hash
        return event_hash

    def finalize(self, *, metrics: dict[str, Any], summary: str) -> Path:
        self.write_json("metrics.json", metrics)
        (self.path / "summary.md").write_text(summary.rstrip() + "\n")
        metrics_valid, metric_errors, reproduced = verify_results(self.path)
        self.write_json(
            "verification.json",
            {
                "schema_version": "1.0",
                "verifier": "independent-record-recalculation-v1",
                "status": "PASS" if metrics_valid else "FAIL",
                "errors": metric_errors,
                "reproduced_metrics": reproduced,
            },
        )
        missing = [name for name in PACKAGE_FILES if not (self.path / name).exists()]
        if missing:
            raise RuntimeError(f"evidence package incomplete before manifest: {missing}")
        files = {
            path.name: _file_hash(path)
            for path in sorted(self.path.iterdir())
            if path.name != "manifest.json"
        }
        manifest_body = {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "generated_at": utc_now().isoformat(),
            "hash_algorithm": "sha256",
            "chain_heads": self._heads,
            "files": files,
        }
        manifest = {
            **manifest_body,
            "manifest_hash": hashlib.sha256(canonical_json(manifest_body).encode()).hexdigest(),
        }
        self.write_json("manifest.json", manifest)
        return self.path


def verify_evidence(path: Path) -> tuple[bool, list[str]]:
    """Verify required files, hashes, chains, schemas, and request correlation."""
    errors: list[str] = []
    manifest_path = path / "manifest.json"
    if not manifest_path.exists():
        return False, ["manifest.json missing"]
    try:
        manifest = _load_json(manifest_path)
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"manifest invalid: {exc}"]
    body = {key: value for key, value in manifest.items() if key != "manifest_hash"}
    expected_manifest_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    if manifest.get("manifest_hash") != expected_manifest_hash:
        errors.append("manifest hash mismatch")
    for name in PACKAGE_FILES:
        if name not in manifest.get("files", {}):
            errors.append(f"required file not manifested: {name}")
    for name, expected in manifest.get("files", {}).items():
        target = path / name
        if not target.exists():
            errors.append(f"missing file: {name}")
        elif _file_hash(target) != expected:
            errors.append(f"file hash mismatch: {name}")

    payloads: dict[str, list[dict[str, Any]]] = {}
    for name in JSONL_FILES:
        previous = "0" * 64
        target = path / name
        payloads[name] = []
        if not target.exists():
            errors.append(f"missing stream: {name}")
            continue
        for line_number, line in enumerate(target.read_text().splitlines(), start=1):
            try:
                record = json.loads(line)
                event_hash = record.pop("event_hash")
                payload = record["payload"]
                if not isinstance(payload, dict):
                    raise TypeError("payload must be an object")
                payloads[name].append(payload)
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                errors.append(f"invalid record: {name}:{line_number}: {exc}")
                continue
            if record.get("previous_hash") != previous:
                errors.append(f"chain discontinuity: {name}:{line_number}")
            calculated = hashlib.sha256(canonical_json(record).encode()).hexdigest()
            if event_hash != calculated:
                errors.append(f"event hash mismatch: {name}:{line_number}")
            previous = event_hash
        if previous != manifest.get("chain_heads", {}).get(name):
            errors.append(f"chain head mismatch: {name}")

    request_sets: dict[str, set[str]] = {}
    for name in ("proposals.jsonl", "decisions.jsonl", "executions.jsonl", "invariants.jsonl"):
        ids = [item.get("request_id") for item in payloads.get(name, [])]
        if any(not isinstance(item, str) for item in ids):
            errors.append(f"request_id missing or invalid: {name}")
        string_ids = [item for item in ids if isinstance(item, str)]
        if len(string_ids) != len(set(string_ids)):
            errors.append(f"duplicate request_id: {name}")
        request_sets[name] = set(string_ids)
    proposal_ids = request_sets.get("proposals.jsonl", set())
    for name in ("decisions.jsonl", "executions.jsonl", "invariants.jsonl"):
        if request_sets.get(name, set()) != proposal_ids:
            errors.append(f"request correlation mismatch: {name}")

    metrics_valid, metric_errors, _ = verify_results(path)
    if not metrics_valid:
        errors.extend(metric_errors)
    return not errors, errors
