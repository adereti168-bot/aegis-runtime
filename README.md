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
    return f"Refunded \${amount} to {email}"

adapter = AegisAgentAdapter(aegis)

# 1. Export schemas for OpenAI / Groq / LangGraph or Anthropic
openai_tools = adapter.to_openai_tools()
anthropic_tools = adapter.to_anthropic_tools()

# 2. Safely execute incoming LLM tool calls or n8n webhook payloads
response = adapter.execute_tool_call("issue_refund", '{"amount": 500, "email": "user@example.com"}')
```
