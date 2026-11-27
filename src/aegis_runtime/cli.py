import argparse
import hashlib
import json
import sys
from aegis_runtime.core import AegisRuntime, GENESIS_HASH
from aegis_runtime.mcp_proxy import AegisMCPProxy, run_interactive_demo


def verify_audit_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Audit file not found: {filepath}")
        return 1
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in audit file: {e}")
        return 1

    if not isinstance(entries, list) or len(entries) == 0:
        print("[ERROR] Audit log is empty or invalid format.")
        return 1

    expected_prev_hash = GENESIS_HASH

    for i, entry in enumerate(entries):
        if "hash" not in entry or "prev_hash" not in entry:
            print(f"[TAMPER DETECTED] Entry #{i} is missing cryptographic hash fields.")
            return 1

        if entry["prev_hash"] != expected_prev_hash:
            print(f"[TAMPER DETECTED] Broken hash chain at entry #{i} (tool='{entry.get('tool')}').")
            print(f"  Expected prev_hash: {expected_prev_hash}")
            print(f"  Found prev_hash:    {entry['prev_hash']}")
            return 1

        recorded_hash = entry["hash"]
        payload = {k: v for k, v in entry.items() if k != "hash"}
        canonical = json.dumps(payload, sort_keys=True)
        computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if recorded_hash != computed_hash:
            print(f"[TAMPER DETECTED] Payload modified at entry #{i} (tool='{entry.get('tool')}').")
            print(f"  Recorded hash: {recorded_hash}")
            print(f"  Computed hash: {computed_hash}")
            return 1

        expected_prev_hash = recorded_hash

    print(f"[VERIFIED] Audit log '{filepath}' is 100% intact ({len(entries)} hash-chained entries).")
    print(f"           Head SHA-256: {expected_prev_hash}")
    return 0


def harden_audit_file(filepath, out_path):
    if verify_audit_file(filepath) != 0:
        print("[ABORTED] Refusing to synthesize policy from tampered or invalid audit log.")
        return 1
    entries = json.loads(open(filepath, "r", encoding="utf-8").read())
    pol = AegisRuntime.synthesize_policy(entries)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(pol, f, indent=2)
    print(f"[HARDENED] Synthesized policy with {len(pol['rules'])} tool rule(s) -> {out_path}")
    return 0

def main():
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis Runtime CLI — Deterministic Flight Controller & Audit Verifier",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify cryptographic integrity of an exported Aegis SHA-256 audit log"
    )
    verify_parser.add_argument("filepath", help="Path to the exported JSON audit log file")

    harden_parser = subparsers.add_parser("harden", help="Synthesize hardened Policy-as-Code from a verified audit log")
    harden_parser.add_argument("filepath", help="Path to verified JSON audit log")
    harden_parser.add_argument("-o", "--output", default="aegis_policy.synthesized.json", help="Output policy JSON path")

    demo_parser = subparsers.add_parser("demo", help="Run a live deterministic exfiltration-block & SHA-256 audit demo")
    demo_parser.add_argument("-o", "--output", default="aegis_demo_audit.json", help="Output demo audit log path")

    mcp_parser = subparsers.add_parser("mcp-proxy", help="Wrap any stdio MCP server with deterministic Aegis guardrails")
    mcp_parser.add_argument("-p", "--policy", default=None, help="Path to aegis_policy.json")
    mcp_parser.add_argument("-o", "--audit-out", default="aegis_mcp_audit.json", help="Audit log output path")
    mcp_parser.add_argument("--telemetry-url", default=None, help="Optional Aegis Cloud telemetry URL")
    mcp_parser.add_argument("--api-key", default=None, help="Optional Aegis Cloud API key")
    mcp_parser.add_argument("server_cmd", nargs=argparse.REMAINDER, help="Command to launch target MCP server (e.g. -- python server.py)")

    args = parser.parse_args()
    if args.command == "demo":
        sys.exit(run_interactive_demo(args.output))
    if args.command == "mcp-proxy":
        cmd = args.server_cmd[1:] if args.server_cmd and args.server_cmd[0] == "--" else args.server_cmd
        if not cmd:
            print("[ERROR] Provide an MCP server command, e.g.: aegis mcp-proxy -- python server.py")
            sys.exit(1)
        proxy = AegisMCPProxy(cmd, policy_path=args.policy, audit_out=args.audit_out, telemetry_url=args.telemetry_url, api_key=args.api_key)
        sys.exit(proxy.run())
    if args.command == "verify":
        sys.exit(verify_audit_file(args.filepath))
    if args.command == "harden":
        sys.exit(harden_audit_file(args.filepath, args.output))


if __name__ == "__main__":
    main()
