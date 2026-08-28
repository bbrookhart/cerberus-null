# Limitations

- The environment is synthetic and the adapters are in-memory mocks.
- The HMAC signer is local; production key management and workload identity are unimplemented.
- Python process boundaries do not substitute for hardware-backed or kernel-enforced isolation.
- No external LLM or MCP server is required or evaluated in the committed baseline.
- Provenance is recorded but full information-flow tracking through a model is not possible here.
- The policy engine is an explicit in-project implementation, not a formally verified solver.
- The TLA+ model is finite and abstract; TLC results do not prove Python equivalence.
- The authorization kernel is assumed trusted and host compromise is out of scope.
- The evaluation set is finite and deliberately benign with respect to real-world exploit payloads.
- Framework mappings communicate research coverage; they are not compliance, certification, or risk acceptance.
- A zero measured escape rate is conditional evidence, not proof of universal safety.
