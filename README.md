# Aegis Runtime (`aegis-runtime`) v0.9.0

**Zero-trust deterministic flight controller and autonomous behavioral defense for AI agents** featuring causal exfiltration guards, statistical anomaly detection, self-hardening policy synthesis, circuit breakers, state locks, human-in-the-loop approval gates, atomic rollbacks, and SHA-256 tamper-proof audit logs with zero external dependencies.

```bash
pip install aegis-runtime
```

## What's New in v0.8.0

* **Zero-Config MCP Onboarding (`aegis init` & `aegis mcp-config`)**: Scaffold a starter `aegis_policy.json` in one command (`aegis init`) and generate or merge wrapped `mcpServers` configs for Claude Desktop and Cursor (`aegis mcp-config --write .cursor/mcp.json -- python server.py`).
* **Zero-Dependency `stdio` MCP Firewall (`aegis mcp-proxy`)**: Wrap any MCP server over JSON-RPC (`aegis mcp-proxy --policy aegis_policy.json -- python server.py`) to intercept `tools/call` requests, block causal exfiltration, and emit tamper-proof SHA-256 audit logs-or test live with `aegis demo`.

## What's New in v0.6.0

* **Causal Exfiltration & Sequence Guards (`forbid_after` / `require_sequence`)**: Block multi-step data exfiltration chains (forbidding `send_webhook` after `read_secrets` -> `BLOCKED_EXFILTRATION`) and enforce strict tool call ordering (`BLOCKED_SEQUENCE`).
* **Statistical Behavioral Anomaly Detector (`anomaly_multiplier`)**: Automatically learn rolling parameter baselines via `statistics.mean` and block sudden behavioral spikes (`BLOCKED_ANOMALY`) before execution.
* **Autonomous Policy Synthesizer (`aegis harden`)**: Compile verified SHA-256 production audit logs directly into hardened `aegis_policy.json` guardrails via `AegisRuntime.synthesize_policy()` or `aegis harden audit.json -o aegis_policy.synthesized.json`.

## Core Features & Quickstart

Aegis enforces hard deterministic rules in Python prior to sensitive tool execution to prevent indirect prompt injections, multi-step exfiltration, and runaway loops.

```python
from aegis_runtime import AegisRuntime

aegis = AegisRuntime(max_calls=5)

@aegis.guard()
def read_customer_db(query: str):
    return 'sensitive_records'

@aegis.guard(forbid_after=['read_customer_db'])
def post_external_webhook(url: str, payload: str):
    return f'Posted to {url}'

@aegis.guard(anomaly_multiplier=3.0, require_approval=True)
def issue_refund(amount: float, user_id: str):
    return f'Refunded ${amount} to {user_id}'
```

* **Policy-as-Code (`aegis_policy.json`)**: Define rules, required state flags, argument limits, sequence rules, and approval requirements externally.
* **Human-in-the-Loop & Universal Adapters**: Attach approval callbacks or export tool schemas for OpenAI, Anthropic, Groq, LangGraph, and n8n.
* **Atomic Time-Travel Rollbacks (`@aegis.transaction`)**: Automatically rewind state stores if a multi-step workflow fails.
* **Cryptographic Verification & Hardening CLI**: Verify SHA-256 hash-chained audit logs (`aegis verify audit.json`) and synthesize hardened policies (`aegis harden audit.json`).

## Aegis Cloud Control Plane (Live Hosted Sandbox)

Stream SHA-256 hash-chained audit logs and trigger remote Human-in-the-Loop approval gates from any Python agent:

1. Open the live control plane at **https://aegis-cloud-lzcu.onrender.com** and click **Generate Free API Key** (or test immediately with `aegis_live_demo_key_001`).
2. Connect `AegisRuntime` to your isolated workspace:

```python
from aegis_runtime import AegisRuntime

aegis = AegisRuntime(
    telemetry_url='https://aegis-cloud-lzcu.onrender.com/v1/events',
    api_key='aegis_live_demo_key_001',
)

@aegis.guard(max_args={'amount': 500}, require_approval=True)
def transfer_funds(amount: float, recipient: str):
    return f'Sent \${amount} to {recipient}'
```

## License

MIT License

## v0.7.0: Zero-Dependency MCP Firewall & Instant CLI Demo

Test deterministic exfiltration blocking and SHA-256 audit verification in one command:

```bash
aegis demo
aegis verify aegis_demo_audit.json
```

Wrap any `stdio` MCP server (Claude Desktop, Cursor, Windsurf, custom agents) with deterministic guardrails without changing server code:

```bash
aegis mcp-proxy --policy aegis_policy.json -- python my_mcp_server.py
```
