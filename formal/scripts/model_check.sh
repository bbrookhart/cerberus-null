#!/usr/bin/env bash
set -euo pipefail

formal_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repository_root="$(cd "$formal_root/.." && pwd)"
tool_directory="$repository_root/.tools"
tool_jar="$tool_directory/tla2tools.jar"
tool_url="https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
tool_sha256="eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a"
positive_log="$formal_root/results/positive-tlc.log"
negative_log="$formal_root/results/negative-tlc.log"
report="$formal_root/results/v0.1-model-check.md"

mkdir -p "$tool_directory" "$formal_root/results" "$formal_root/states"
if [[ ! -f "$tool_jar" ]]; then
  curl --fail --location --silent --show-error --retry 3 --output "$tool_jar" "$tool_url"
fi
printf '%s  %s\n' "$tool_sha256" "$tool_jar" | sha256sum --check --status

rm -rf "$formal_root/states/positive" "$formal_root/states/negative"
mkdir -p "$formal_root/states/positive" "$formal_root/states/negative"

(
  cd "$formal_root"
  java -cp "$tool_jar" tlc2.TLC \
    -workers 1 \
    -noGenerateSpecTE \
    -metadir states/positive \
    -config CerberusNull.cfg \
    CerberusNull.tla
) | tee "$positive_log"

if ! grep -q "Model checking completed. No error has been found" "$positive_log"; then
  echo "positive model did not complete successfully" >&2
  exit 1
fi

set +e
(
  cd "$formal_root"
  java -cp "$tool_jar" tlc2.TLC \
    -workers 1 \
    -noGenerateSpecTE \
    -metadir states/negative \
    -config CerberusNullBroken.cfg \
    CerberusNullBroken.tla
) >"$negative_log" 2>&1
negative_status=$?
set -e

if [[ "$negative_status" -eq 0 ]] || ! grep -q "Invariant F1_UnauthorizedNeverExecutes is violated" "$negative_log"; then
  echo "known-broken mutation did not produce the expected F1 counterexample" >&2
  cat "$negative_log" >&2
  exit 1
fi

states_line="$(grep -E '[0-9]+ states generated, [0-9]+ distinct states found' "$positive_log" | tail -1)"
depth_line="$(grep -E 'depth of the complete state graph search' "$positive_log" | tail -1)"
version_line="$(grep -E '^TLC2 Version' "$positive_log" | head -1)"
spec_hash="$(sha256sum "$formal_root/CerberusNull.tla" | awk '{print $1}')"
configuration_hash="$(sha256sum "$formal_root/CerberusNull.cfg" | awk '{print $1}')"
checked_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
machine="$(uname -srm)"

cat >"$report" <<EOF
# CERBERUS NULL v0.1 model-check result

- Checked at: \`$checked_at\`
- TLC: \`$version_line\`
- Specification SHA-256: \`$spec_hash\`
- Configuration SHA-256: \`$configuration_hash\`
- Model: one agent, one human issuer, four action classes, two resources, two
  capability issuers, four approval states, and Boolean emergency-stop state.
- Search: $states_line
- Graph: $depth_line
- Machine: \`$machine\`

## Result

**PASS.** TLC found no invariant violation for TypeOK or F1-F7 over every
reachable state in the bounded configuration.

| Property | Result |
|---|---|
| F1 Unauthorized action never executes | PASS |
| F2 Exact approval is required | PASS |
| F3 Emergency stop blocks consequential execution | PASS |
| F4 Agent cannot increase its capability | PASS |
| F5 T4 cannot execute autonomously | PASS |
| F6 Execution requires audit precommit | PASS |
| F7 Approval hash binds the request | PASS |

## Formal mutation validation

**PASS.** \`CerberusNullBroken.tla\` adds a known authorization-bypass transition.
TLC produced the expected F1 counterexample, demonstrating that the core
invariant suite is capable of detecting this material defect. The broken
transition is excluded from the release specification.

## Interpretation boundary

This result establishes that the TLA+ authorization model satisfies the listed
invariants over all reachable states within the finite bounds above. It does not
prove that the Python implementation is equivalent or that the system is
universally secure. Implementation property tests and EXP-CN-001 provide separate
evidence for those claims.
EOF

echo "Formal model check and negative mutation validation passed."
