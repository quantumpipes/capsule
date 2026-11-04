#!/usr/bin/env python3
"""
Generate the ML-DSA-65 signature conformance vectors (CPS Section 3.3).

Run from the repo root (needs liboqs-python):
    python conformance/generate_pq_fixtures.py

Outputs pq-signature-fixtures.json beside this script. A throwaway ML-DSA-65 key
signs the hash strings of two golden vectors from fixtures.json. Only the public
key and the signatures are written; the private key is discarded. ML-DSA signing
is hedged, so each run produces different signatures, and every run's output is
equally valid.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import oqs

HERE = Path(__file__).parent
CONTEXT = b"capsule"  # a non-empty context; CPS 3.3 signs with an empty one


def main() -> None:
    """Build the vectors and write pq-signature-fixtures.json beside this script."""
    golden = json.loads((HERE / "fixtures.json").read_text())["fixtures"]
    a, b = golden[0], golden[1]
    signer = oqs.Signature("ML-DSA-65")
    public_key = signer.generate_keypair()

    def sign(h: str) -> str:
        return signer.sign(h.encode("utf-8")).hex()

    sig_a = sign(a["sha3_256_hash"])
    flipped = bytearray(bytes.fromhex(sig_a))
    flipped[100] ^= 0x01
    with_ctx = signer.sign_with_ctx_str(a["sha3_256_hash"].encode("utf-8"), CONTEXT).hex()

    cases = [
        {"name": f"valid_{a['name']}", "hash": a["sha3_256_hash"], "signature_pq": sig_a, "valid": True},
        {"name": f"valid_{b['name']}", "hash": b["sha3_256_hash"], "signature_pq": sign(b["sha3_256_hash"]), "valid": True},
        {"name": "signature_for_another_hash", "hash": b["sha3_256_hash"], "signature_pq": sig_a, "valid": False},
        {"name": "one_bit_flipped", "hash": a["sha3_256_hash"], "signature_pq": flipped.hex(), "valid": False},
        {"name": "non_empty_context", "hash": a["sha3_256_hash"], "signature_pq": with_ctx, "valid": False},
        {"name": "truncated", "hash": a["sha3_256_hash"], "signature_pq": sig_a[:-2], "valid": False},
        {"name": "not_hex", "hash": a["sha3_256_hash"], "signature_pq": "zz" + sig_a[2:], "valid": False},
    ]
    out = {
        "version": "1.0",
        "specification": "CPS 1.0 Section 3.3",
        "generated_by": f"liboqs-python {oqs.oqs_python_version()} (liboqs {oqs.oqs_version()})",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "description": (
            "ML-DSA-65 (FIPS 204) signatures over the UTF-8 bytes of a capsule's "
            "64-character SHA3-256 hex hash, with an empty context. A verifier must "
            "accept every case marked valid and reject every other case."
        ),
        "algorithm": "ML-DSA-65",
        "public_key": public_key.hex(),
        "cases": cases,
    }
    (HERE / "pq-signature-fixtures.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {len(cases)} cases")


if __name__ == "__main__":
    main()
