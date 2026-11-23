import json
import os
import subprocess
import sys
from aegis_runtime import AegisRuntime, SecurityViolation


def security_officer_approval(tool_name, args, context):
    """Simulated Slack / Aegis Cloud human-in-the-loop approval callback."""
    amount = args.get("amount", 0)
    if amount > 2000:
        print(f"  [HUMAN REVIEW] SecOps Officer (@alice) REJECTED {tool_name} (${amount} exceeds manual review comfort)")
        return False, "secops_alice"
    print(f"  [HUMAN REVIEW] SecOps Officer (@alice) APPROVED {tool_name} (${amount})")
    return True, "secops_alice"


def main():
    print("=== AEGIS RUNTIME v0.5.0: HUMAN-IN-THE-LOOP & FIELD FORENSICS DEMO ===\n")

    aegis = AegisRuntime(
        max_calls=5,
        approval_handler=security_officer_approval,
    )

    @aegis.guard(
        requires_state={"mfa_verified": True},
        max_args={"amount": 5000},
        require_approval=True,
    )
    def wire_treasury_funds(amount: float, recipient: str) -> str:
        return f"Wired ${amount} to {recipient}"

    # 1. Blocked by State Lock -> records violated_field='mfa_verified'
    try:
        wire_treasury_funds(1500, "vendor@acme.io")
    except SecurityViolation as e:
        last = aegis.audit_log[-1]
        print(f"[BLOCKED] {e}")
        print(f"          Forensic violated_field = '{last['violated_field']}'\n")

    # Unlock MFA state
    aegis.session_state["mfa_verified"] = True

    # 2. Blocked by Human-in-the-Loop Gate -> records approver & approval_status='DENIED'
    try:
        wire_treasury_funds(3500, "vendor@acme.io")
    except SecurityViolation as e:
        last = aegis.audit_log[-1]
        print(f"[BLOCKED] {e}")
        print(f"          Approver = '{last['approver']}' | Status = '{last['approval_status']}'\n")

    # 3. Approved by Human-in-the-Loop Gate -> executes & hashes approver into SHA-256 chain
    outcome = wire_treasury_funds(1500, "vendor@acme.io")
    last = aegis.audit_log[-1]
    print(f"[ALLOWED] {outcome}")
    print(f"          Approver = '{last['approver']}' | Status = '{last['approval_status']}'\n")

    # 4. Export and cryptographically verify the SHA-256 hash chain
    audit_file = "v050_demo_audit.json"
    aegis.export_audit_log(audit_file)
    subprocess.run([sys.executable, "-m", "aegis_runtime.cli", "verify", audit_file], check=True)

    if os.path.exists(audit_file):
        os.remove(audit_file)


if __name__ == "__main__":
    main()
