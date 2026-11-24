# 🛡 Aegis Runtime (`aegis-runtime`) v0.5.0

**Zero-trust deterministic flight controller for AI agents** featuring circuit breakers, state locks, human-in-the-loop approval gates, Policy-as-Code, atomic state rollbacks, and SHA-256 tamper-proof audit logs with zero external dependencies.

```bash
pip install aegis-runtime
```

## Core Features & Quickstart

Aegis enforces hard deterministic rules in Python prior to sensitive tool execution to prevent indirect prompt injections and runaway loops. 

* **Policy-as-Code (`aegis_policy.json`)**: Define rules, required state flags, argument limits, and approval requirements externally.
* **Human-in-the-Loop & Universal Adapters**: Attach approval callbacks or export tool schemas for OpenAI, Anthropic, Groq, LangGraph, and n8n.
* **Atomic Time-Travel Rollbacks (`@aegis.transaction`)**: Automatically rewind state stores if a multi-step workflow fails.
* **Cryptographic Verification**: Export and verify SHA-256 hash-chained compliance audit logs via the CLI (`aegis verify audit.json`).

For full implementation details, policy schemas, and code examples, please refer to the complete documentation in the repository's `README.md`.

## Aegis Cloud Control Plane (Live Hosted Sandbox)

Stream SHA-256 hash-chained audit logs and trigger remote Human-in-the-Loop approval gates from any Python agent:

1. Open the live control plane at **https://aegis-cloud-lzcu.onrender.com** and click **Generate Free API Key** (or test immediately with `aegis_live_demo_key_001`).
2. Connect `AegisRuntime` to your isolated workspace:

```python
from aegis_runtime import AegisRuntime

aegis = AegisRuntime(
    telemetry_url="https://aegis-cloud-lzcu.onrender.com/v1/events",
    api_key="aegis_live_demo_key_001",
)

@aegis.guard(max_args={"amount": 500}, require_approval=True)
def transfer_funds(amount: float, recipient: str):
    return f"Sent ${amount} to {recipient}"
```

## License

MIT License
