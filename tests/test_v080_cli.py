import json
import os
import subprocess
import sys
import tempfile
import unittest
from aegis_runtime.cli import init_policy_file, generate_mcp_config
from aegis_runtime.core import AegisRuntime

class TestV080CLI(unittest.TestCase):
    def test_init_and_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as d:
            pol_path = os.path.join(d, 'aegis_policy.json')
            self.assertEqual(init_policy_file(pol_path), 0)
            self.assertTrue(os.path.exists(pol_path))
            rt = AegisRuntime.from_policy(pol_path)
            self.assertIn('send_external_email', rt.policy.get('rules', {}))
            self.assertEqual(init_policy_file(pol_path, force=False), 1)
            self.assertEqual(init_policy_file(pol_path, force=True), 0)

    def test_mcp_config_merge_and_fail_closed(self):
        self.assertEqual(generate_mcp_config('srv', 'aegis_policy.json', []), 1)
        with tempfile.TemporaryDirectory() as d:
            cfg_path = os.path.join(d, '.cursor', 'mcp.json')
            os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
            with open(cfg_path, 'w', encoding='utf-8') as f:
                json.dump({'mcpServers': {'existing': {'command': 'node', 'args': ['x.js']}}}, f)
            rc = generate_mcp_config('db-server', 'aegis_policy.json', ['python', 'db.py'], write_path=cfg_path)
            self.assertEqual(rc, 0)
            with open(cfg_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.assertIn('existing', data['mcpServers'])
            self.assertEqual(data['mcpServers']['db-server']['command'], 'aegis')
            self.assertEqual(data['mcpServers']['db-server']['args'], ['mcp-proxy', '--policy', 'aegis_policy.json', '--', 'python', 'db.py'])

    def test_cli_subprocess_commands(self):
        with tempfile.TemporaryDirectory() as d:
            pol_path = os.path.join(d, 'pol.json')
            r1 = subprocess.run([sys.executable, '-m', 'aegis_runtime.cli', 'init', '-o', pol_path], capture_output=True, text=True)
            self.assertEqual(r1.returncode, 0)
            self.assertIn('[INIT]', r1.stdout)
            r2 = subprocess.run([sys.executable, '-m', 'aegis_runtime.cli', 'mcp-config', '--name', 'fs', '-p', pol_path, '--', 'npx', '-y', '@modelcontextprotocol/server-filesystem', '.'], capture_output=True, text=True)
            self.assertEqual(r2.returncode, 0)
            self.assertIn('mcp-proxy', r2.stdout)

if __name__ == '__main__':
    unittest.main()
