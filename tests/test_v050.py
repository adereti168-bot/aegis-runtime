import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from aegis_runtime import AegisRuntime, SecurityViolation


def test_violated_field_forensics():
    aegis = AegisRuntime(max_calls=3)

    @aegis.guard(requires_state={"mfa_verified": True}, max_args={"amount": 1000})
    def transfer_funds(amount: float, recipient: str) -> str:
        return f"Sent ${amount} to {recipient}"

    # 1. Trigger state lock violation
    try:
        transfer_funds(500, "alice@corp.com")
        assert False, "Expected SecurityViolation for missing mfa_verified"
    except SecurityViolation:
        pass

    assert aegis.audit_log[-1]["status"] == "BLOCKED_POLICY"
    assert aegis.audit_log[-1]["violated_field"] == "mfa_verified"

    # 2. Unlock state, then trigger max_args threshold violation
    aegis.session_state["mfa_verified"] = True
    try:
        transfer_funds(5000, "alice@corp.com")
        assert False, "Expected SecurityViolation for amount ceiling"
    except SecurityViolation:
        pass

    assert aegis.audit_log[-1]["status"] == "BLOCKED_THRESHOLD"
    assert aegis.audit_log[-1]["violated_field"] == "amount"


def test_human_in_the_loop_approval_gate():
    # Case A: Custom handler denies then approves
    decision = {"allow": False, "user": "sec_ops_alice"}

    def mock_approver(tool_name, args, context):
        return (decision["allow"], decision["user"])

    aegis = AegisRuntime(approval_handler=mock_approver)

    @aegis.guard(require_approval=True)
    def delete_production_db(cluster: str) -> str:
        return f"Dropped {cluster}"

    # Denied attempt
    try:
        delete_production_db("prod-eu-1")
        assert False, "Expected SecurityViolation when human denies approval"
    except SecurityViolation:
        pass

    last_denied = aegis.audit_log[-1]
    assert last_denied["status"] == "BLOCKED_APPROVAL"
    assert last_denied["approver"] == "sec_ops_alice"
    assert last_denied["approval_status"] == "DENIED"
    assert last_denied["violated_field"] == "human_approval"

    # Approved attempt
    decision["allow"] = True
    out = delete_production_db("prod-eu-1")
    assert out == "Dropped prod-eu-1"

    last_approved = aegis.audit_log[-1]
    assert last_approved["status"] == "EXECUTED"
    assert last_approved["approver"] == "sec_ops_alice"
    assert last_approved["approval_status"] == "APPROVED"


def test_policy_json_approval_and_telemetry_sink():
    received_events = []
    received_auth = []

    class TelemetryHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8")
            received_events.append(json.loads(raw))
            received_auth.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), TelemetryHandler)
    port = server.server_address[1]
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()

    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "policy_v050.json")
        audit_path = os.path.join(tmpdir, "audit_v050.json")

        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "max_calls": 5,
                    "rules": {
                        "wire_payout": {
                            "max_args": {"amount": 2500},
                            "require_approval": True,
                        }
                    },
                },
                f,
            )

        aegis = AegisRuntime.from_policy(
            policy_path,
            approval_handler=lambda tool, args, ctx: (True, "cfo_bob"),
            telemetry_url=f"http://127.0.0.1:{port}/v1/events",
            api_key="ag_test_secret_123",
        )

        @aegis.guard
        def wire_payout(amount: float, vendor: str) -> str:
            return f"Wired ${amount} to {vendor}"

        res = wire_payout(1200, "Acme Cloud")
        assert res == "Wired $1200 to Acme Cloud"

        # Wait briefly for daemon telemetry thread to deliver POST
        for _ in range(20):
            if received_events:
                break
            time.sleep(0.05)

        server.shutdown()

        assert len(received_events) == 1
        assert received_events[0]["tool"] == "wire_payout"
        assert received_events[0]["approver"] == "cfo_bob"
        assert received_events[0]["approval_status"] == "APPROVED"
        assert received_auth[0] == "Bearer ag_test_secret_123"

        # Verify CLI tamper check still passes on v0.5.0 extended audit fields
        aegis.export_audit_log(audit_path)
        proc = subprocess.run(
            [sys.executable, "-m", "aegis_runtime.cli", "verify", audit_path],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"CLI verify failed: {proc.stdout} {proc.stderr}"
        print(proc.stdout.strip())


if __name__ == "__main__":
    test_violated_field_forensics()
    test_human_in_the_loop_approval_gate()
    test_policy_json_approval_and_telemetry_sink()
    print("ALL v0.5.0 HUMAN-IN-THE-LOOP, FORENSICS & TELEMETRY TESTS PASSED!")
