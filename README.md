# Titan Gate

Titan Gate is the commit history for AI decisions.

Every code change evaluated by an AI system produces a **receipt** — a signed, chained, Merkle-anchored artifact that proves what was evaluated, what verdict was reached, and that the record has not been altered.

Receipts are independently verifiable by any party with access to the receipt file and the signing key. No network access, no database, no trusted third party required.

---

## Verify a Receipt
```
pip install titan-gate
titan-verify receipt.json --key <hex_key>
```

Or run directly:
```
python titan/verify.py receipt.json --key <hex_key>
```

Expected output:
```
============================================================
TITAN GATE RECEIPT VERIFICATION
============================================================
Receipt ID   : tv1-genesis
Tenant       : tenant_test
Repo         : tenant/test-repo
Verdict      : PASS
Score        : 0.88
Evaluated At : 2026-03-04T10:00:00Z
------------------------------------------------------------
VERIFICATION  : PASS
Signature     : VALID
Hash          : VALID
============================================================
```

---

## Example Receipts

Test vectors with known-good hashes and signatures are in `examples/`:

| File | Verdict | Key |
|------|---------|-----|
| TV1.json | PASS | `00...00` (64 zeros) |
| TV2.json | WARN | `00...00` (64 zeros) |
| TV3.json | PASS | `00...00` (64 zeros) |

Verify all three:
```
python titan/verify.py examples/TV1.json --key 0000000000000000000000000000000000000000000000000000000000000000
python titan/verify.py examples/TV2.json --key 0000000000000000000000000000000000000000000000000000000000000000
python titan/verify.py examples/TV3.json --key 0000000000000000000000000000000000000000000000000000000000000000
```

---

## Specification

Full cryptographic specification: [SPEC.md](SPEC.md)

Covers: receipt format, canonical JSON serialization, HMAC-SHA256 signing, Merkle ledger construction, anchor files, verification algorithm, SOC2 control mappings.

---

## Architecture

Titan Gate consists of five cryptographic verification layers:

1. **Deterministic evaluation** — three-judge scoring engine
2. **Signed receipts** — HMAC-SHA256 over canonical JSON
3. **Receipt chaining** — append-only chain via `prev_receipt_hash`
4. **Merkle ledger** — daily Merkle root over all receipts
5. **Anchor notarization** — sealed roots stored in Git

---

## SOC2 Alignment

| Control | Coverage |
|---------|----------|
| CC6.1 | Tenant isolation, API key as SHA256 |
| CC6.7 | HMAC-SHA256 signature over canonical bytes |
| CC7.2 | Replay engine, chain integrity verification |
| CC8.1 | Signed receipt per PR, verdict + score recorded |

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Specification — CC BY 4.0
```

Once all four files are saved, confirm:
```
Get-ChildItem C:\Users\rmaso\Projects\titan-gate-public -Recurse