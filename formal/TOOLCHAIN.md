# Formal verification toolchain provenance

CERBERUS NULL verifies the TLA+ tool JAR before running TLC. This file records a reproducibility boundary discovered on 2026-09-06: the upstream `v1.8.0` GitHub release asset changed after the original CERBERUS NULL v0.1 formal run.

## Historical v0.1 run

The CERBERUS NULL v0.1 release was completed in August 2026. At that time, `formal/scripts/model_check.sh` downloaded:

`https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar`

and required SHA-256:

`eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a`

That digest passed in the original CI/research-release environment and is part of the historical toolchain identity of the committed v0.1 formal evidence.

Do not rewrite the historical result to pretend that it used a later asset.

## Upstream change discovered 2026-09-06

A documentation-only research PR caused the formal CI gate to fail before TLC emitted output. All Python lint, type, unit/property/adversarial tests, container checks, supply-chain checks and CodeQL passed. Investigation showed the failure occurred at the SHA-256 gate.

GitHub's API for `tlaplus/tlaplus` now reports the `v1.8.0` release as:

- release id: `25926686`
- release name: `The Clarke release`
- created: `2026-09-04T16:54:20Z`
- published: `2026-09-04T17:13:14Z`
- `immutable: false`

and the current `tla2tools.jar` asset as:

- asset id: `544648411`
- asset name: `tla2tools.jar`
- SHA-256: `b658b4e504fdf0b721caf7066320f6b6fe5805f4dd2f717d0e47baba4097205e`
- created: `2026-09-04T17:12:06Z`

Source of record for this update: GitHub Releases API for `tlaplus/tlaplus`, retrieved 2026-09-06.

Because the release is not immutable and the same tag/download URL now identifies bytes with a different digest, that URL alone is insufficient to identify the historical August tool artifact.

## Current policy

1. **Never disable the checksum gate to make CI green.**
2. Pin the currently verified release asset by SHA-256 and record its GitHub asset ID.
3. On checksum mismatch, print both expected and actual digest and stop.
4. Treat the August v0.1 tool digest as historical provenance, not as a claim that the old bytes remain retrievable from the same upstream URL.
5. A current re-run with the current `v1.8.0` asset is a **semantic reproduction of the same bounded specification/configuration using a new tool artifact**, not a byte-identical reproduction of the historical toolchain.
6. Record current TLC version, tool digest, specification digest, configuration digest, state counts, graph depth and known-broken counterexample result in every new formal evidence package.
7. For EXP-CN-002 and later releases, archive or otherwise persist the exact formal verification artifact used by the release when licensing and repository policy permit; a mutable upstream tag is not sufficient archival provenance.

## Recovery of the historical artifact

If the earlier `eabd140a...` JAR is later recovered from a trusted CI cache, archival artifact, or other provenance-preserving source, verify its digest before use and archive it with its provenance. Do not accept a matching filename or version label as evidence of identity.

Until then, exact historical tool-byte reproduction is listed as unavailable; the committed specification, configuration, implementation tests and v0.1 evidence remain separately inspectable.
