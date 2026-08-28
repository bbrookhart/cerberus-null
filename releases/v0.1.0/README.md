# CERBERUS NULL v0.1.0 release artifacts

This snapshot gathers the formal and empirical headline artifacts for review.
Canonical machine-readable evidence remains in
`evidence/EXP-CN-001-v0.1.0/`; the copies here are convenience release assets.

- `formal/`: bounded TLC model-check report, positive log, and detected
  counterexample from the known-broken mutation;
- `experiment/`: EXP-CN-001 comparison, summary, and evidence manifest;
- `figures/`: formal-state-machine and compromised-planner result figures;
- `metrics.json`: primary measured results;
- `verification.json`: independently reproduced security metrics.

Run `make results` to model-check the specification and verify the canonical
evidence package.
