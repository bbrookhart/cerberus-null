"""Coherent, scriptable command-line interface."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cerberus_null import __version__
from cerberus_null.evaluation import list_evaluations, run_evaluations
from cerberus_null.evidence import verify_evidence
from cerberus_null.models import IdentityKind
from cerberus_null.runtime import build_runtime


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def _state_path() -> Path:
    return Path(os.getenv("CERBERUS_STATE_DIR", ".cerberus")) / "emergency-stop.json"


def _serve(port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path not in {"/health", "/status"}:
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(
                {"status": "healthy", "version": __version__, "environment": "synthetic-only"}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    bind_host = os.getenv("CERBERUS_BIND_HOST", "127.0.0.1")
    ThreadingHTTPServer((bind_host, port), Handler).serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cerberus", description="CERBERUS NULL control plane")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")

    mission = sub.add_parser("mission")
    mission_sub = mission.add_subparsers(dest="mission_command", required=True)
    mission_sub.add_parser("list")

    capability = sub.add_parser("capability")
    capability_sub = capability.add_subparsers(dest="capability_command", required=True)
    capability_sub.add_parser("inspect")

    evaluation = sub.add_parser("evaluation")
    evaluation_sub = evaluation.add_subparsers(dest="evaluation_command", required=True)
    evaluation_sub.add_parser("list")
    run = evaluation_sub.add_parser("run")
    run.add_argument("target", help="EVAL-001..EVAL-012 or all")
    run.add_argument("--output", type=Path, default=Path("evidence"))
    run.add_argument("--run-id")

    evidence = sub.add_parser("evidence")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    for action in ("inspect", "verify"):
        child = evidence_sub.add_parser(action)
        child.add_argument("path", type=Path)

    stop = sub.add_parser("emergency-stop")
    stop_sub = stop.add_subparsers(dest="stop_command", required=True)
    stop_sub.add_parser("status")
    stop_sub.add_parser("engage")
    stop_sub.add_parser("release")

    demo = sub.add_parser("demo")
    demo.add_argument("--output", type=Path, default=Path("evidence"))
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8080)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    runtime = build_runtime(state_file=_state_path())
    if args.command == "status":
        _print(
            {
                "name": "CERBERUS NULL",
                "version": __version__,
                "policy": "healthy" if runtime.policy_health.healthy else "untrusted",
                "emergency_stop": runtime.emergency_stop.engaged,
                "execution_environment": "synthetic-only",
            }
        )
    elif args.command == "mission":
        _print([mission.model_dump(mode="json") for mission in runtime.missions.list()])
    elif args.command == "capability":
        _print(runtime.capabilities.inspect())
    elif args.command == "evaluation" and args.evaluation_command == "list":
        _print(list_evaluations())
    elif args.command == "evaluation" and args.evaluation_command == "run":
        _print(run_evaluations(args.target, output_root=args.output, run_id=args.run_id))
    elif args.command == "evidence":
        if args.evidence_command == "inspect":
            _print(json.loads((args.path / "metrics.json").read_text()))
        else:
            valid, errors = verify_evidence(args.path)
            _print({"valid": valid, "errors": errors})
            if not valid:
                raise SystemExit(1)
    elif args.command == "emergency-stop":
        operator = runtime.identities.resolve("human-operator-01", IdentityKind.HUMAN)
        if operator is None:
            raise RuntimeError("configured operator identity is unavailable")
        if args.stop_command == "engage":
            runtime.emergency_stop.engage(operator)
        elif args.stop_command == "release":
            runtime.emergency_stop.release(operator)
        _print({"engaged": runtime.emergency_stop.engaged})
    elif args.command == "demo":
        _print(run_evaluations("all", output_root=args.output))
    elif args.command == "serve":
        _serve(args.port)


if __name__ == "__main__":
    main()
