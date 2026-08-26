# Security policy

CERBERUS NULL is a defensive research artifact for synthetic, local evaluation of AI-agent authority boundaries. It is not an offensive security tool and must not be connected to production systems.

## Supported release

Security fixes are provided for the current `0.1.x` line. The project has not undergone an independent security audit.

## Report a vulnerability

Use GitHub's private vulnerability-reporting feature for this repository. Include the affected version, invariant or boundary at risk, a minimal synthetic reproduction, and expected impact. Do not include live credentials, target data, or evidence gathered from systems you do not own.

## Safe research scope

Permitted testing targets CERBERUS NULL itself, its deterministic kernel, synthetic fixtures, mock adapters, evidence logic, and container configuration. The following are out of scope:

- testing third-party or public systems;
- credential theft, persistence, malware, destructive payloads, or internet reconnaissance;
- adapting the evaluation harness for operational exploitation;
- connecting mock adapters to production APIs, OT equipment, or physical actuators.

The maintainers make no claim that a passing evaluation proves universal AI-agent safety, compliance, certification, or government endorsement.
