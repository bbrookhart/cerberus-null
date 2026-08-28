"""Run deterministic security-control mutations against targeted regression tests."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    module: str
    original: str
    replacement: str
    test: str


MUTATIONS = (
    Mutation(
        "MUT-CAP-EXPIRY",
        "authority.py",
        "if not (grant.valid_from <= now < grant.expires_at):",
        "if False:",
        "tests/adversarial/test_evaluations.py::test_full_adversarial_suite_has_zero_unsafe_escape",
    ),
    Mutation(
        "MUT-APPROVAL-BINDING",
        "authority.py",
        "if artifact.request_hash != envelope.request_hash:",
        "if False:",
        "tests/unit/test_approval.py::test_request_change_invalidates_approval",
    ),
    Mutation(
        "MUT-EMERGENCY-STOP",
        "policy.py",
        "if self._emergency_stop.engaged and spec.risk_tier > RiskTier.T0:",
        "if False:",
        "tests/unit/test_emergency_stop.py::test_stop_blocks_consequential_execution",
    ),
    Mutation(
        "MUT-T4-PROHIBITION",
        "policy.py",
        "if not spec.autonomous_execution or spec.risk_tier is RiskTier.T4:",
        "if False:",
        "tests/unit/test_policy.py::test_t4_action_has_no_executable_path",
    ),
    Mutation(
        "MUT-GATEWAY-MEDIATION",
        "gateway.py",
        "if authorization.decision is not Decision.ALLOW:",
        "if False:",
        "tests/integration/test_gateway.py::test_denied_request_does_not_mutate_environment",
    ),
)


def run_mutation(repository: Path, mutation: Mutation) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="cerberus-mutation-") as directory:
        isolated = Path(directory)
        shutil.copytree(repository / "cerberus_null", isolated / "cerberus_null")
        shutil.copytree(repository / "tests", isolated / "tests")
        target = isolated / "cerberus_null" / mutation.module
        source = target.read_text()
        if source.count(mutation.original) != 1:
            raise RuntimeError(f"mutation anchor changed: {mutation.mutation_id}")
        target.write_text(source.replace(mutation.original, mutation.replacement, 1))
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(isolated)
        result = subprocess.run(  # noqa: S603 - fixed local interpreter and test path
            [sys.executable, "-m", "pytest", "-q", mutation.test],
            cwd=isolated,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode != 0, output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=Path("docs/mutation-results.md"))
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    results: list[tuple[Mutation, bool, str]] = []
    for mutation in MUTATIONS:
        killed, output = run_mutation(repository, mutation)
        results.append((mutation, killed, output))
        print(f"{mutation.mutation_id}: {'KILLED' if killed else 'SURVIVED'}")

    rows = "\n".join(
        f"| {mutation.mutation_id} | `{mutation.module}` | "
        f"{'KILLED' if killed else 'SURVIVED'} | `{mutation.test}` |"
        for mutation, killed, _ in results
    )
    args.report.write_text(
        f"""# Security-control mutation results

The harness makes one deliberate control-removal mutation at a time in an
isolated copy and requires the targeted regression test to fail.

| Mutation | Component | Result | Detecting test |
|---|---|---|---|
{rows}

Killed: {sum(killed for _, killed, _ in results)}/{len(results)}

These targeted mutations test the most consequential v0.1 failure modes. This is
not a repository-wide mutation score.
"""
    )
    survivors = [mutation.mutation_id for mutation, killed, _ in results if not killed]
    if survivors:
        raise SystemExit(f"surviving mutations: {', '.join(survivors)}")


if __name__ == "__main__":
    main()
