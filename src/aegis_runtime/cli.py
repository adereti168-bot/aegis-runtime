import argparse
import hashlib
import json
import sys
from aegis_runtime.core import AegisRuntime, GENESIS_HASH


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

    args = parser.parse_args()
    if args.command == "verify":
        sys.exit(verify_audit_file(args.filepath))
    if args.command == "harden":
        sys.exit(harden_audit_file(args.filepath, args.output))


if __name__ == "__main__":
    main()
