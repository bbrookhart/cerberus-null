"""Hash-chained evaluation evidence and package verification."""

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
    "execution.jsonl",
)


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


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
    errors: list[str] = []
    manifest_path = path / "manifest.json"
    if not manifest_path.exists():
        return False, ["manifest.json missing"]
    manifest = json.loads(manifest_path.read_text())
    body = {key: value for key, value in manifest.items() if key != "manifest_hash"}
    expected_manifest_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    if manifest.get("manifest_hash") != expected_manifest_hash:
        errors.append("manifest hash mismatch")
    for name, expected in manifest.get("files", {}).items():
        target = path / name
        if not target.exists() or _file_hash(target) != expected:
            errors.append(f"file hash mismatch: {name}")
    for name in JSONL_FILES:
        previous = "0" * 64
        target = path / name
        if not target.exists():
            errors.append(f"missing stream: {name}")
            continue
        for line_number, line in enumerate(target.read_text().splitlines(), start=1):
            record = json.loads(line)
            event_hash = record.pop("event_hash")
            if record.get("previous_hash") != previous:
                errors.append(f"chain discontinuity: {name}:{line_number}")
            calculated = hashlib.sha256(canonical_json(record).encode()).hexdigest()
            if event_hash != calculated:
                errors.append(f"event hash mismatch: {name}:{line_number}")
            previous = event_hash
        if previous != manifest.get("chain_heads", {}).get(name):
            errors.append(f"chain head mismatch: {name}")
    return not errors, errors
