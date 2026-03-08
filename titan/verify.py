#!/usr/bin/env python3
"""
Titan Gate Receipt Verifier
Zero-dependency standalone verifier for TRS-1 receipts.
https://github.com/Rehanrana11/titan-gate
"""
import argparse
import hashlib
import hmac
import json
import sys
import os

SCHEMA_VERSION = "receipt_v1"
SIGNING_VERSION = "hmac-sha256-v1"
EXCLUSION_FIELDS = {"signature", "receipt_hash", "prev_receipt_hash_verified", "_debug", "_meta"}

REQUIRED_FIELDS = [
    "schema_version", "receipt_id", "tenant_id", "repo", "repo_full_name",
    "pr_number", "evaluated_at", "root_date", "engine_version",
    "merkle_algorithm", "signing_version", "structural_score", "semantic_score",
    "composite_score", "verdict", "hard_violations", "process_violations",
    "artifact_hash", "scope_hash", "provenance_hash", "prev_receipt_hash",
    "receipt_hash", "signature",
]


def canonical_bytes(receipt):
    filtered = {k: v for k, v in receipt.items() if k not in EXCLUSION_FIELDS}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_receipt_hash(receipt):
    return hashlib.sha256(canonical_bytes(receipt)).hexdigest()


def verify_signature(receipt, key_hex):
    key_bytes = bytes.fromhex(key_hex)
    canon = canonical_bytes(receipt)
    expected = hmac.new(key_bytes, canon, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, receipt.get("signature", ""))


def validate(receipt, key_hex):
    errors = []

    if receipt.get("schema_version") != SCHEMA_VERSION:
        errors.append("ERR_SCHEMA_VERSION")

    for field in REQUIRED_FIELDS:
        if field not in receipt:
            errors.append("ERR_SCHEMA_INVALID: missing " + field)

    if receipt.get("signing_version") != SIGNING_VERSION:
        errors.append("ERR_SIGNING_VERSION_UNKNOWN")

    sig = receipt.get("signature", "")
    if len(sig) != 64:
        errors.append("ERR_SIG_INVALID_LENGTH")

    for field in ["receipt_hash", "signature", "artifact_hash", "scope_hash", "provenance_hash"]:
        val = receipt.get(field, "")
        if isinstance(val, str) and len(val) > 0 and val != "GENESIS":
            if val != val.lower():
                errors.append("ERR_HEX_CASE_INVALID: " + field)

    computed_hash = compute_receipt_hash(receipt)
    if computed_hash != receipt.get("receipt_hash"):
        errors.append("ERR_HASH")

    try:
        if not verify_signature(receipt, key_hex):
            errors.append("ERR_SIG")
    except Exception:
        errors.append("ERR_SIG")

    prev = receipt.get("prev_receipt_hash", "")
    if prev != "GENESIS" and len(prev) != 64:
        errors.append("ERR_CHAIN")

    return errors


def print_result(receipt, errors, verbose=False):
    rid = receipt.get("receipt_id", "unknown")
    tenant = receipt.get("tenant_id", "unknown")
    repo = receipt.get("repo_full_name", "unknown")
    verdict = receipt.get("verdict", "unknown")
    score = receipt.get("composite_score", "unknown")
    evaluated = receipt.get("evaluated_at", "unknown")

    print("=" * 60)
    print("TITAN GATE RECEIPT VERIFICATION")
    print("=" * 60)
    print("Receipt ID   : " + rid)
    print("Tenant       : " + tenant)
    print("Repo         : " + repo)
    print("Verdict      : " + str(verdict))
    print("Score        : " + str(score))
    print("Evaluated At : " + evaluated)
    print("-" * 60)

    if not errors:
        print("VERIFICATION  : PASS")
        print("Signature     : VALID")
        print("Hash          : VALID")
    else:
        print("VERIFICATION  : FAIL")
        for e in errors:
            print("  ERROR: " + e)

    if verbose and errors:
        print("-" * 60)
        print("Errors (" + str(len(errors)) + "):")
        for e in errors:
            print("  " + e)

    print("=" * 60)
    return len(errors) == 0


def main():
    parser = argparse.ArgumentParser(
        description="Titan Gate Receipt Verifier - TRS-1",
        epilog="Verifies HMAC signature and hash integrity of a Titan Gate receipt."
    )
    parser.add_argument("receipt", help="Path to receipt JSON file")
    parser.add_argument("--key", required=True, help="HMAC signing key (hex string)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", dest="json_output", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.receipt):
        print("ERROR: File not found: " + args.receipt, file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.receipt, "r", encoding="utf-8") as f:
            receipt = json.load(f)
    except json.JSONDecodeError as e:
        print("ERROR: Invalid JSON: " + str(e), file=sys.stderr)
        sys.exit(2)

    try:
        bytes.fromhex(args.key)
    except ValueError:
        print("ERROR: ERR_KEY_INVALID - key must be hex string", file=sys.stderr)
        sys.exit(2)

    errors = validate(receipt, args.key)

    if args.json_output:
        output = {
            "ok": len(errors) == 0,
            "receipt_id": receipt.get("receipt_id"),
            "tenant_id": receipt.get("tenant_id"),
            "verdict": receipt.get("verdict"),
            "composite_score": receipt.get("composite_score"),
            "errors": errors,
        }
        print(json.dumps(output, indent=2))
        sys.exit(0 if not errors else 1)

    ok = print_result(receipt, errors, verbose=args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
