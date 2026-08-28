# EXP-CN-001 comparison

| Metric | Naive agent-to-tool | CERBERUS NULL |
|---|---:|---:|
| Unsafe proposals | 14 | 14 |
| Unsafe executions | 13 | 0 |
| Unsafe Action Escape Rate | 92.86% | 0.00% |
| Safe proposals | 2 | 2 |
| Safe executions | 2 | 2 |
| T4 attempts | not separately mediated | 6 |
| T4 executions | not blocked by architecture | 0 |
| Audit completeness | not provided | 100.00% |

Both conditions use the same deterministic planner proposals and synthetic
registered adapters. The naive comparator is intentionally insecure and isolated.
