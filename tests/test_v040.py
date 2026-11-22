import json
import os
import tempfile
from aegis_runtime import AegisRuntime, SecurityViolation
from aegis_runtime.cli import verify_audit_file


def test_policy_as_code_and_tamper_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "aegis_policy.json")
        audit_path = os.path.join(tmpdir, "audit.json")

        # 1. Define Policy-as-Code JSON
        policy_data = {
            "max_calls": 3,
            "rules": {
                "approve_kyc": {
                    "sets_state": {"kyc_verified": True}
                },
                "wire_funds": {
                    "requires_state": {"kyc_verified": True},
                    "max_args": {"amount": 10000}
                }
            }
        }
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump(policy_data, f)

        # 2. Initialize runtime strictly from JSON policy
        aegis = AegisRuntime.from_policy(policy_path)

        @aegis.guard
        def approve_kyc(user_id: str) -> str:
            return f"KYC approved for {user_id}"

        @aegis.guard
        def wire_funds(amount: float, recipient: str) -> str:
            return f"Wired ${amount} to {recipient}"

        # 3. Verify state lock from JSON policy blocks unverified transfer
        try:
            wire_funds(500, "alice@company.com")
            assert False, "Expected SecurityViolation for missing kyc_verified state"
        except SecurityViolation as e:
            assert "requires kyc_verified=True" in str(e)

        # 4. Approve KYC and verify numeric ceiling from JSON policy blocks $25,000
        approve_kyc("USR-101")
        try:
            wire_funds(25000, "alice@company.com")
            assert False, "Expected SecurityViolation for exceeding max_args ceiling"
        except SecurityViolation as e:
            assert "exceeds max allowed 10000" in str(e)

        # 5. Execute valid transfer within policy ceiling ($5,000 <= $10,000)
        res = wire_funds(5000, "alice@company.com")
        assert res == "Wired $5000 to alice@company.com"

        # 6. Export SHA-256 hash-chained audit log and verify intactness
        aegis.export_audit_log(audit_path)
        assert verify_audit_file(audit_path) == 0, "Valid audit log failed verification!"

        # 7. Simulate insider tampering with the audit log JSON
        with open(audit_path, "r", encoding="utf-8") as f:
            tampered_log = json.load(f)
        tampered_log[-1]["args"] = "(500000, 'attacker@offshore.io')"
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(tampered_log, f)

        assert verify_audit_file(audit_path) == 1, "Tampered audit log was not detected!"

    print("ALL v0.4.0 POLICY-AS-CODE & CLI VERIFIER TESTS PASSED!")


if __name__ == "__main__":
    test_policy_as_code_and_tamper_detection()
