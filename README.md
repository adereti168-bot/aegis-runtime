# 🛡️ Aegis Runtime (`aegis-runtime`)

**Zero-trust deterministic flight controller for AI agents.**  
Circuit breakers, deterministic state locks, Policy-as-Code, atomic state rollbacks, and SHA-256 tamper-proof audit logs—with **zero external dependencies**.

```bash
pip install aegis-runtime
```

---

## Why Aegis?
Prompt-level guardrails are probabilistic—sooner or later, an indirect prompt injection or runaway loop slips past the LLM. **Aegis** enforces hard deterministic rules in Python before any sensitive tool executes.

---

## 🚀 Quickstart: Policy-as-Code & Hash-Chained Audit Logs (v0.4.0)

Define security rules in a standalone `aegis_policy.json` file without touching agent code:

```json
{
  "max_calls": 5,
  "rules": {
    "verify_customer": {
      "sets_state": { "customer_verified": true }
    },
    "issue_refund": {
      "requires_state": { "customer_verified": true },
      "max_args": { "amount": 10000 }
    }
  }
}
```

Load the policy, guard your tools, and export a tamper-evident SHA-256 hash chain:

```python
from aegis_runtime import AegisRuntime

aegis = AegisRuntime.from_policy("aegis_policy.json")

@aegis.guard
def verify_customer(email: str) -> str:
    return f"Verified {email}"

@aegis.guard
def issue_refund(amount: float, email: str) -> str:
    return f"Refunded ${amount} to {email}"

verify_customer("user@example.com")
issue_refund(500, "user@example.com")

# Export hash-chained compliance log
aegis.export_audit_log("audit.json")
```

Verify cryptographic integrity from any terminal:

```bash
aegis verify audit.json
```

---

## 🔌 Universal Agent Adapters (OpenAI, Anthropic, Groq, LangGraph & n8n)

```python
from aegis_runtime import AegisRuntime, AegisAgentAdapter

aegis = AegisRuntime()

@aegis.guard(sets_state={"customer_verified": True})
def verify_customer(email: str) -> str:
    """Verify customer identity before sensitive actions."""
    return f"Verified {email}"

@aegis.guard(requires_state={"customer_verified": True})
def issue_refund(amount: float, email: str) -> str:
    """Issue a refund to a verified customer."""
    return f"Refunded ${amount} to {email}"

adapter = AegisAgentAdapter(aegis)

# 1. Export schemas for OpenAI / Groq / LangGraph or Anthropic
openai_tools = adapter.to_openai_tools()
anthropic_tools = adapter.to_anthropic_tools()

# 2. Safely execute incoming LLM tool calls or n8n webhook payloads
response = adapter.execute_tool_call("issue_refund", '{"amount": 500, "email": "user@example.com"}')
```

---

## ⏪ Atomic Time-Travel Rollbacks (`@aegis.transaction`)

Wrap multi-step workflows so that if step 3 fails, steps 1 and 2 automatically rewind to zero:

```python
@aegis.transaction("onboarding_flow")
def run_workflow():
    step_1_provision_db()
    step_2_allocate_credits()
    step_3_failing_call()  # Automatically rewinds state_store to pre-transaction snapshot
```

---

## License
MIT License
