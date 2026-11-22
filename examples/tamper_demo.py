import json
import os
import subprocess
from aegis_runtime import AegisRuntime, SecurityViolation

# 1. Write standalone Policy-as-Code JSON
policy = {
    "max_calls": 5,
    "rules": {
        "verify_kyc": {"sets_state": {"kyc_verified": True}},
        "wire_funds": {
            "requires_state": {"kyc_verified": True},
            "max_args": {"amount": 10000}
        }
    }
}
with open("demo_policy.json", "w", encoding="utf-8") as f:
    json.dump(policy, f, indent=2)

# 2. Boot Aegis Flight Controller from JSON policy
aegis = AegisRuntime.from_policy("demo_policy.json")

@aegis.guard
def verify_kyc(vendor: str) -> str:
    return f"KYC passed for {vendor}"

@aegis.guard
def wire_funds(amount: float, recipient: str) -> str:
    return f"Wired ${amount:,.2f} to {recipient}"

print("=" * 72)
print("[AEGIS v0.4.0] POLICY-AS-CODE & SHA-256 TAMPER DETECTION DEMO")
print("=" * 72)

verify_kyc("Acme Cloud")
print("[ALLOWED] verify_kyc('Acme Cloud')")

try:
    wire_funds(50000, "attacker@offshore.io")
except SecurityViolation as e:
    print(f"[BLOCKED] wire_funds($50,000) -> {e}")

wire_funds(2500, "billing@acme.io")
print("[ALLOWED] wire_funds($2,500) within $10,000 policy ceiling\n")

# 3. Export SHA-256 hash-chained audit log
aegis.export_audit_log("demo_audit.json")
print(">> Running CLI verifier on clean audit log:")
subprocess.run(["aegis", "verify", "demo_audit.json"])

# 4. Simulate rogue insider altering $2,500 -> $999,999 in demo_audit.json
print("\n[!] Simulating insider tampering with demo_audit.json ($2,500 -> $999,999)...")
with open("demo_audit.json", "r", encoding="utf-8") as f:
    data = json.load(f)
data[-1]["args"] = "(999999, 'attacker@offshore.io')"
with open("demo_audit.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(">> Re-running CLI verifier on tampered audit log:")
subprocess.run(["aegis", "verify", "demo_audit.json"])
print("=" * 72)

# Cleanup temporary demo files
os.remove("demo_policy.json")
os.remove("demo_audit.json")
