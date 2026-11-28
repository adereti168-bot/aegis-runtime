import copy
import json
import os
import tempfile
import unittest
from aegis_runtime.core import AegisRuntime
from aegis_runtime.cli import verify_audit_file
from aegis_runtime.mcp_proxy import AegisMCPProxy


class TestV090HmacAttestation(unittest.TestCase):
    def test_hmac_signing_and_verification(self):
        secret = "test_hmac_secret_key_99"
        rt = AegisRuntime(signing_secret=secret)

        @rt.guard
        def ping(x):
            return x

        self.assertEqual(ping(42), 42)
        self.assertEqual(len(rt.audit_log), 1)
        self.assertIn("hmac_sig", rt.audit_log[0])

        ok, msg = AegisRuntime.verify_audit_entries(rt.audit_log, signing_secret=secret)
        self.assertTrue(ok, msg)
        self.assertIn("HMAC-SHA256 attested", msg)

    def test_hmac_rejects_wrong_secret_and_forged_rehash(self):
        secret = "prod_secret_abc"
        rt = AegisRuntime(signing_secret=secret)

        @rt.guard
        def transfer(amount):
            return amount

        transfer(10)
        ok_wrong, _ = AegisRuntime.verify_audit_entries(rt.audit_log, signing_secret="wrong_secret")
        self.assertFalse(ok_wrong)

        forged = copy.deepcopy(rt.audit_log)
        forged[0]["args"] = "{'amount': 999999}"
        import hashlib
        base = {k: v for k, v in forged[0].items() if k not in ("hash", "hmac_sig")}
        forged[0]["hash"] = hashlib.sha256(json.dumps(base, sort_keys=True).encode("utf-8")).hexdigest()
        ok_forged, msg_forged = AegisRuntime.verify_audit_entries(forged, signing_secret=secret)
        self.assertFalse(ok_forged)
        self.assertIn("Invalid HMAC", msg_forged)

    def test_cli_verify_and_mcp_proxy_secret(self):
        secret = "cli_secret_xyz"
        proxy = AegisMCPProxy(["python", "-V"], signing_secret=secret)
        proxy.evaluate_rpc_line(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "safe_read", "arguments": {"q": "hi"}}}))
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(proxy.runtime.audit_log, tmp)
            tmp_path = tmp.name
        try:
            self.assertEqual(verify_audit_file(tmp_path, signing_secret=secret), 0)
            self.assertEqual(verify_audit_file(tmp_path, signing_secret="bad"), 1)
        finally:
            os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
