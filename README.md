# 🛡️ Aegis Runtime (`aegis-runtime`)

**The zero-trust deterministic flight controller for AI agents.**

Enterprises refuse to deploy fully autonomous AI agents in production because probabilistic LLMs suffer from three fatal flaws:
1. **Prompt Injections & Unauthorized Actions:** Malicious inputs trick agents into wiring funds, issuing refunds, or deleting records.
2. **Infinite Loops & Partial Corruption:** Agents spiral in tool-call loops or crash mid-workflow, leaving databases in corrupted states.
3. **Zero Compliance Guarantees:** Regulated industries (fintech, healthcare, legal) require deterministic code enforcement and tamper-proof audit trails—not probabilistic "hope."

**Aegis treats the LLM like a brilliant, erratic intern.** Every tool call is wrapped in deterministic Python code (`@aegis.guard` and `@aegis.transaction`) that enforces hard mathematical guarantees before any side effect touches your infrastructure.

---

## ⚡ Core Capabilities

* **Deterministic State Locks:** Enforce code-level prerequisites (`issue_refund` cannot execute unless `verify_customer` succeeded in the same session).
* **Circuit Breakers:** Hard execution caps on repetitive tool calls to kill infinite loops instantly.
* **Atomic Time-Travel Rollbacks:** Automatic state snapshots before multi-step workflows—if Step 3 fails, Steps 1 and 2 rewind automatically.
* **Cryptographic Audit Logs:** Every allowed or blocked tool execution generates a tamper-proof **SHA-256 hash receipt**.
* **Zero External Dependencies:** Pure Python standard library core (`0` bloated dependencies).

---

## 🚀 Quickstart

```bash
pip install aegis-runtime
```

```python
from aegis_runtime import AegisRuntime, SecurityViolation

aegis = AegisRuntime()

@aegis.guard(max_calls=3)
def verify_customer(email: str) -> str:
    aegis.set_state("customer_verified", True)
    return f"Verified {email}"

@aegis.guard(requires=["customer_verified"])
def issue_refund(amount: float, email: str) -> str:
    return f"Refunded ${amount} to {email}"
```

---

## 🔥 Live Proof: Neutralizing an Indirect Prompt Injection

In `examples/live_agent.py`, a 120B frontier LLM is compromised by a hidden CRM metadata injection attempting to bypass customer verification and send **\$5,000**. Aegis intercepts the compromised tool call in deterministic Python and logs a SHA-256 receipt:

```text
[AI ATTEMPTED TOOL CALL] issue_refund({'amount': 5000, 'email': 'sarah.m@gmail.com'})

[AEGIS SHIELD ACTIVATED] Live AI Compromised, Attack Neutralized!
Reason: Policy violation: issue_refund requires customer_verified=True

Cryptographic Audit Log:
{'timestamp': 1795043630.3087144, 'tool': 'issue_refund', 'status': 'BLOCKED_POLICY', 'args': '()', 'hash': 'c58f693e73d0032529ce47cb9d9ad6a664cc73368f6f9e919719727b6909a23d'}
```

---

## 🧪 Running the Examples

```bash
# 1. Test deterministic blocking of unauthorized database deletion
python examples/test_attack.py

# 2. Test atomic time-travel state rollback on mid-transaction failure
python examples/test_rollback.py

# 3. Test live prompt injection defense against an LLM (requires GROQ_API_KEY in .env)
pip install groq
python examples/live_agent.py
```

---

## 🗺️ Roadmap

- [x] **v0.2:** Deterministic State Locks, Circuit Breakers, Atomic Rollbacks, SHA-256 Audit Receipts
- [ ] **v0.3:** Native adapters for OpenAI, Anthropic, LangGraph, and CrewAI
- [ ] **v0.4:** Policy-as-Code YAML/JSON configurations & CLI audit verifier
- [ ] **Aegis Cloud:** Real-time fleet observability, live human-in-the-loop approvals, and one-click replay

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
