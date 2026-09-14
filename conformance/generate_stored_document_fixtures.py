#!/usr/bin/env python3
"""
Generate the stored-document conformance vector (CPS Section 3.5).

Run from the repo root:
    python conformance/generate_stored_document_fixtures.py

Outputs stored-document-fixtures.json beside this script. The vector is a synthetic
record sealed before ``spec_version`` joined the canonical content, signed with a fixed
test key, so any implementation can check that it verifies the stored document rather
than a re-serialized model.
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from nacl.signing import SigningKey

from qp_capsule import Capsule, CapsuleType, OutcomeSection, ReasoningSection, TriggerSection

# A fixed test key derived from a public seed. It signs this vector and nothing else.
TEST_SEED = hashlib.sha3_256(b"cps-conformance/stored-document/test-key").digest()


def canonical_json(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha3_256_hex(s: str) -> str:
    return hashlib.sha3_256(s.encode("utf-8")).hexdigest()


def main() -> None:
    capsule = Capsule(
        id=UUID("5d0c7a3e-2b1f-4c8e-9a6d-3f1e7b2c4d5a"),
        type=CapsuleType.AGENT,
        domain="agents",
        sequence=0,
        previous_hash=None,
        trigger=TriggerSection(
            type="user_request",
            source="conformance",
            timestamp=datetime(2026, 3, 7, 12, 0, tzinfo=UTC),
            request="Summarize the quarterly report",
        ),
        reasoning=ReasoningSection(
            options_considered=["summarize", "defer"],
            selected_option="summarize",
            reasoning="The report is ready.",
            confidence=0.9,
        ),
        outcome=OutcomeSection(status="success", summary="Summary drafted"),
    )
    model_document = capsule.to_dict()
    stored_document = {k: v for k, v in model_document.items() if k != "spec_version"}

    stored_json = canonical_json(stored_document)
    stored_hash = sha3_256_hex(stored_json)
    model_json = canonical_json(model_document)
    model_hash = sha3_256_hex(model_json)

    key = SigningKey(TEST_SEED)
    signature = key.sign(stored_hash.encode("utf-8")).signature.hex()
    public_key = key.verify_key.encode().hex()
    sealed_record = {
        **stored_document,
        "hash": stored_hash,
        "signature": signature,
        "signature_pq": "",
        "signed_at": "2026-03-07T12:00:01+00:00",
        "signed_by": public_key[:16],
    }

    output = {
        "version": "1.0",
        "specification": "CPS v1.0 Section 3.5",
        "generated_by": "conformance/generate_stored_document_fixtures.py",
        "description": (
            "A record sealed before spec_version joined the canonical content. A conformant "
            "verifier hashes the stored document, so the record verifies; hashing a model "
            "that fills in spec_version yields a different hash."
        ),
        "fixtures": [
            {
                "name": "sealed_before_spec_version",
                "description": (
                    "Stored document without spec_version, its model re-serialization with "
                    'spec_version "1.0", and an Ed25519 test signature over the stored hash.'
                ),
                "stored_document": stored_document,
                "canonical_json": stored_json,
                "sha3_256_hash": stored_hash,
                "model_document": model_document,
                "model_canonical_json": model_json,
                "model_sha3_256_hash": model_hash,
                "public_key_hex": public_key,
                "signature_hex": signature,
                "sealed_record": sealed_record,
            }
        ],
    }
    out = Path(__file__).with_name("stored-document-fixtures.json")
    out.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {out} ({stored_hash} stored, {model_hash} model)")


if __name__ == "__main__":
    main()
