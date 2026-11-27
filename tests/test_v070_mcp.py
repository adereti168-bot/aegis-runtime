import io
import json
import os
import sys
import tempfile
import unittest
from aegis_runtime import AegisMCPProxy
from aegis_runtime.cli import verify_audit_file
from aegis_runtime.mcp_proxy import run_interactive_demo


class TestAegisMCPProxy(unittest.TestCase):
    def test_mcp_proxy_blocks_exfiltration_and_logs_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = os.path.join(tmp, 'policy.json')
            audit_path = os.path.join(tmp, 'audit.json')
            server_script = os.path.join(tmp, 'echo_mcp.py')
            policy = {
                'rules': {
                    'read_db': {'max_calls': 2},
                    'send_email': {'forbid_after': ['read_db']},
                }
            }
            with open(policy_path, 'w', encoding='utf-8') as f:
                json.dump(policy, f)
            srv_code = [
                'import json, sys',
                'for line in sys.stdin:',
                '    msg = json.loads(line)',
                '    resp = dict(jsonrpc=str(2.0), id=msg.get(chr(105)+chr(100)), result=dict(ok=True, tool=(msg.get(chr(112)+chr(97)+chr(114)+chr(97)+chr(109)+chr(115)) or {}).get(chr(110)+chr(97)+chr(109)+chr(101))))',
                '    print(json.dumps(resp), flush=True)',
            ]
            with open(server_script, 'w', encoding='utf-8') as f:
                f.write(chr(10).join(srv_code) + chr(10))
            req1 = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'read_db', 'arguments': {'q': 'users'}}})
            req2 = json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'send_email', 'arguments': {'to': 'evil@example.com'}}})
            fake_in = io.StringIO(req1 + chr(10) + req2 + chr(10))
            fake_out = io.StringIO()
            proxy = AegisMCPProxy([sys.executable, server_script], policy_path=policy_path, audit_out=audit_path)
            rc = proxy.run(stdin=fake_in, stdout=fake_out)
            self.assertEqual(rc, 0)
            out_lines = [json.loads(x) for x in fake_out.getvalue().strip().splitlines()]
            self.assertEqual(len(out_lines), 2)
            by_id = {m['id']: m for m in out_lines}
            self.assertEqual(by_id[1]['result']['tool'], 'read_db')
            self.assertIn('error', by_id[2])
            self.assertEqual(by_id[2]['error']['code'], -32003)
            self.assertEqual(verify_audit_file(audit_path), 0)

    def test_interactive_demo_runs_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = os.path.join(tmp, 'demo.json')
            self.assertEqual(run_interactive_demo(audit_path), 0)
            self.assertEqual(verify_audit_file(audit_path), 0)


if __name__ == '__main__':
    unittest.main()
