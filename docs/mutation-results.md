# Security-control mutation results

The harness makes one deliberate control-removal mutation at a time in an
isolated copy and requires the targeted regression test to fail.

| Mutation | Component | Result | Detecting test |
|---|---|---|---|
| MUT-CAP-EXPIRY | `authority.py` | KILLED | `tests/adversarial/test_evaluations.py::test_full_adversarial_suite_has_zero_unsafe_escape` |
| MUT-APPROVAL-BINDING | `authority.py` | KILLED | `tests/unit/test_approval.py::test_request_change_invalidates_approval` |
| MUT-EMERGENCY-STOP | `policy.py` | KILLED | `tests/unit/test_emergency_stop.py::test_stop_blocks_consequential_execution` |
| MUT-T4-PROHIBITION | `policy.py` | KILLED | `tests/unit/test_policy.py::test_t4_action_has_no_executable_path` |
| MUT-GATEWAY-MEDIATION | `gateway.py` | KILLED | `tests/integration/test_gateway.py::test_denied_request_does_not_mutate_environment` |

Killed: 5/5

These targeted mutations test the most consequential v0.1 failure modes. This is
not a repository-wide mutation score.
