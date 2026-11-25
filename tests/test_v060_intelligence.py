import json
import os
import subprocess
import sys
import tempfile

from aegis_runtime import AegisRuntime, SecurityViolation


def test_causal_exfiltration_forbid_after():
    aegis = AegisRuntime()

    @aegis.guard()
    def read_secrets():
        return "SECRET_KEY"

    @aegis.guard(forbid_after=["read_secrets"])
    def send_webhook(url: str):
        return f"Sent to {url}"

    assert send_webhook("https://safe.local") == "Sent to https://safe.local"
    assert read_secrets() == "SECRET_KEY"

    try:
        send_webhook("https://evil.local")
        assert False, "Expected SecurityViolation for forbid_after"
    except SecurityViolation:
        pass

    assert aegis.audit_log[-1]["status"] == "BLOCKED_EXFILTRATION"


def test_require_sequence():
    aegis = AegisRuntime()

    @aegis.guard()
    def verify_user():
        return True

    @aegis.guard(require_sequence=["verify_user"])
    def delete_account():
        return "DELETED"

    try:
        delete_account()
        assert False, "Expected SecurityViolation for require_sequence"
    except SecurityViolation:
        pass

    assert aegis.audit_log[-1]["status"] == "BLOCKED_SEQUENCE"
    assert verify_user() is True
    assert delete_account() == "DELETED"


def test_statistical_anomaly_multiplier():
    aegis = AegisRuntime()

    @aegis.guard(anomaly_multiplier=3.0)
    def refund(amount: float):
        return amount

    assert refund(10.0) == 10.0
    assert refund(12.0) == 12.0
    assert refund(11.0) == 11.0

    try:
        refund(500.0)
        assert False, "Expected SecurityViolation for anomaly_multiplier"
    except SecurityViolation:
        pass

    assert aegis.audit_log[-1]["status"] == "BLOCKED_ANOMALY"


def test_synthesize_policy_and_cli_harden():
    aegis = AegisRuntime()

    @aegis.guard()
    def verify_user():
        return True

    @aegis.guard(max_args={"amount": 50})
    def refund(amount: float):
        return amount

    verify_user()
    refund(40.0)
    try:
        refund(999.0)
    except SecurityViolation:
        pass

    policy = AegisRuntime.synthesize_policy(aegis.audit_log, headroom=1.25)
    assert policy.get("synthesized") is True
    rules = policy["rules"]
    assert rules["refund"]["max_args"]["amount"] == 50.0
    assert rules["refund"]["require_sequence"] == ["verify_user"]
    assert rules["refund"]["require_approval"] is True

    with tempfile.TemporaryDirectory() as tmp:
        audit_path = os.path.join(tmp, "audit.json")
        out_path = os.path.join(tmp, "aegis_policy.synthesized.json")
        aegis.export_audit_log(audit_path)
        res = subprocess.run(
            [sys.executable, "-m", "aegis_runtime.cli", "harden", audit_path, "-o", out_path],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, res.stderr
        assert os.path.exists(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert "refund" in loaded["rules"]
