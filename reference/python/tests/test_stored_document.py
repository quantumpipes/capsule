# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""
Verification hashes the stored document (CPS Section 3.5).

A record read back from storage is verified against the exact content document that
was sealed, not a re-serialization of today's model. Records sealed before a content
field existed keep verifying, and anything stored beside the sealed content is caught.
"""

import hashlib
import json
from pathlib import Path

import pytest
from nacl.signing import VerifyKey
from sqlalchemy import select

from qp_capsule import (
    ADDED_CONTENT_DEFAULTS,
    Capsule,
    attach_stored_document,
    content_for_hash,
    stored_document,
    to_stored_sealed_dict,
)
from qp_capsule.capsule import ReasoningSection, TriggerSection
from qp_capsule.chain import CapsuleChain
from qp_capsule.seal import Seal, SealVerifyCode
from qp_capsule.storage import CapsuleModel, CapsuleStorage

_FIXTURES_PATH = (
    Path(__file__).resolve().parents[3] / "conformance" / "stored-document-fixtures.json"
)


def _sha3(document: dict) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha3_256(canonical.encode("utf-8")).hexdigest()


def _capsule() -> Capsule:
    return Capsule(
        trigger=TriggerSection(type="user_request", source="test", request="Summarize the pilot"),
        reasoning=ReasoningSection(
            options_considered=["a", "b"],
            selected_option="a",
            reasoning="A is ready.",
            confidence=0.9,
        ),
    )


def _pre_spec_version_record(seal: Seal) -> tuple[Capsule, dict]:
    """A record an older writer sealed before spec_version joined the canonical content."""
    document = _capsule().to_dict()
    del document["spec_version"]
    capsule = attach_stored_document(Capsule.from_dict(document), document)
    signing_key, _ = seal._ensure_keys()
    capsule.hash = _sha3(document)
    capsule.signature = signing_key.sign(capsule.hash.encode("utf-8")).signature.hex()
    capsule.signed_by = seal.get_key_fingerprint()
    return capsule, document


class TestRecordsSealedBeforeSpecVersion:
    def test_verify_against_the_stored_document(self, temp_seal: Seal) -> None:
        capsule, _ = _pre_spec_version_record(temp_seal)
        result = temp_seal.verify_detailed(capsule)
        assert result.ok, result.message

    def test_fail_when_verified_from_the_model(self, temp_seal: Seal) -> None:
        capsule, _ = _pre_spec_version_record(temp_seal)
        attach_stored_document(capsule, None)
        assert temp_seal.verify_detailed(capsule).code == SealVerifyCode.HASH_MISMATCH

    def test_explicit_key_verification_uses_the_stored_document(self, temp_seal: Seal) -> None:
        capsule, _ = _pre_spec_version_record(temp_seal)
        assert temp_seal.verify_with_key_detailed(capsule, temp_seal.get_public_key()).ok


class TestChangedAfterLoad:
    def test_verify_detailed_reports_the_change(self, temp_seal: Seal) -> None:
        capsule, _ = _pre_spec_version_record(temp_seal)
        capsule.trigger.request = "Something else"
        result = temp_seal.verify_detailed(capsule)
        assert result.code == SealVerifyCode.HASH_MISMATCH
        assert "changed after it was loaded" in result.message

    def test_explicit_key_path_reports_the_change(self, temp_seal: Seal) -> None:
        capsule, _ = _pre_spec_version_record(temp_seal)
        capsule.outcome.summary = "edited"
        result = temp_seal.verify_with_key_detailed(capsule, temp_seal.get_public_key())
        assert result.code == SealVerifyCode.HASH_MISMATCH

    def test_sealing_again_covers_the_new_content(self, temp_seal: Seal) -> None:
        capsule, _ = _pre_spec_version_record(temp_seal)
        capsule.trigger.request = "Something else"
        temp_seal.seal(capsule)
        assert stored_document(capsule) is None
        assert temp_seal.verify(capsule)


class TestAgreement:
    @staticmethod
    def _loaded() -> tuple[Capsule, dict]:
        capsule = _capsule()
        attach_stored_document(capsule, json.loads(json.dumps(capsule.to_dict())))
        document = stored_document(capsule)
        assert document is not None
        return capsule, document

    def test_fresh_capsule_hashes_its_model(self) -> None:
        capsule = _capsule()
        assert content_for_hash(capsule) == capsule.to_dict()

    def test_agreeing_model_yields_the_stored_document(self) -> None:
        capsule, document = self._loaded()
        assert content_for_hash(capsule) is document

    def test_added_field_holding_its_default_is_tolerated(self) -> None:
        capsule, document = self._loaded()
        del document["spec_version"]
        assert content_for_hash(capsule) is document

    def test_added_field_with_another_value_is_a_change(self) -> None:
        capsule, document = self._loaded()
        del document["spec_version"]
        capsule.spec_version = "2.0"
        assert content_for_hash(capsule) is None

    def test_missing_field_never_added_later_is_a_change(self) -> None:
        capsule, document = self._loaded()
        del document["domain"]
        assert content_for_hash(capsule) is None

    def test_added_defaults_apply_only_at_the_top_level(self) -> None:
        capsule, document = self._loaded()
        del document["trigger"]["request"]
        assert content_for_hash(capsule) is None

    def test_section_replaced_by_a_scalar_is_a_change(self) -> None:
        capsule, document = self._loaded()
        document["trigger"] = "flattened"
        assert content_for_hash(capsule) is None

    def test_list_length_difference_is_a_change(self) -> None:
        capsule, document = self._loaded()
        document["reasoning"]["options_considered"].append("c")
        assert content_for_hash(capsule) is None

    def test_list_replaced_by_a_scalar_is_a_change(self) -> None:
        capsule, document = self._loaded()
        document["reasoning"]["options_considered"] = "a"
        assert content_for_hash(capsule) is None

    def test_list_item_difference_is_a_change(self) -> None:
        capsule, document = self._loaded()
        document["reasoning"]["options_considered"][0] = "z"
        assert content_for_hash(capsule) is None

    def test_extra_stored_keys_stay_in_the_hashed_document(self) -> None:
        capsule, document = self._loaded()
        document["injected"] = "unsigned"
        assert content_for_hash(capsule) is document

    def test_added_defaults_name_spec_version(self) -> None:
        assert ADDED_CONTENT_DEFAULTS == {"spec_version": "1.0"}

    def test_forgetting_is_idempotent_and_non_documents_are_ignored(self) -> None:
        capsule, _ = self._loaded()
        attach_stored_document(capsule, None)
        attach_stored_document(capsule, None)
        assert stored_document(capsule) is None
        capsule.__dict__["_qp_stored_document"] = "not a document"
        assert stored_document(capsule) is None


class TestSealedDicts:
    def test_from_sealed_dict_remembers_its_content(self, temp_seal: Seal) -> None:
        capsule, document = _pre_spec_version_record(temp_seal)
        sealed = to_stored_sealed_dict(capsule)
        assert "spec_version" not in sealed
        restored = Capsule.from_sealed_dict(sealed)
        assert stored_document(restored) == document
        assert temp_seal.verify(restored)

    def test_stored_sealed_dict_falls_back_when_the_model_changed(self, temp_seal: Seal) -> None:
        capsule, _ = _pre_spec_version_record(temp_seal)
        capsule.trigger.request = "Something else"
        assert to_stored_sealed_dict(capsule) == capsule.to_sealed_dict()

    def test_fresh_capsule_stored_sealed_dict_matches_to_sealed_dict(self, temp_seal: Seal) -> None:
        capsule = temp_seal.seal(_capsule())
        assert to_stored_sealed_dict(capsule) == capsule.to_sealed_dict()


class TestConformanceVector:
    @pytest.fixture
    def vector(self) -> dict:
        with open(_FIXTURES_PATH, encoding="utf-8") as handle:
            return json.load(handle)["fixtures"][0]

    def test_stored_document_hashes_to_the_seal(self, vector: dict) -> None:
        assert _sha3(vector["stored_document"]) == vector["sha3_256_hash"]
        assert _sha3(vector["model_document"]) == vector["model_sha3_256_hash"]
        assert vector["model_sha3_256_hash"] != vector["sha3_256_hash"]

    def test_sealed_record_verifies_with_the_test_key(self, tmp_path: Path, vector: dict) -> None:
        capsule = Capsule.from_sealed_dict(vector["sealed_record"])
        seal = Seal(key_path=tmp_path / "unused_key")
        result = seal.verify_with_key_detailed(capsule, vector["public_key_hex"])
        assert result.ok, result.message

    def test_signature_covers_the_stored_hash_string(self, vector: dict) -> None:
        VerifyKey(bytes.fromhex(vector["public_key_hex"])).verify(
            vector["sha3_256_hash"].encode("utf-8"), bytes.fromhex(vector["signature_hex"])
        )


async def _store_one(storage: CapsuleStorage, seal: Seal) -> None:
    capsule = await CapsuleChain(storage).add(_capsule())
    seal.seal(capsule)
    await storage.store(capsule)


async def _rewrite_stored(storage: CapsuleStorage, rewrite) -> None:
    """Change the one stored record in place, the way a direct database write would."""
    await storage._ensure_db()
    factory = storage._get_session_factory()
    async with factory() as session:
        model = (await session.execute(select(CapsuleModel))).scalars().one()
        data = json.loads(model.data)
        rewrite(model, data)
        model.data = json.dumps(data)
        await session.commit()


class TestStorage:
    @pytest.mark.asyncio
    async def test_storage_keeps_the_stored_document(
        self, temp_storage: CapsuleStorage, temp_seal: Seal
    ) -> None:
        await _store_one(temp_storage, temp_seal)
        (loaded,) = await temp_storage.get_all_ordered()
        assert stored_document(loaded) == loaded.to_dict()
        assert temp_seal.verify(loaded)

    @pytest.mark.asyncio
    async def test_record_stored_before_spec_version_verifies_through_the_chain(
        self, temp_storage: CapsuleStorage, temp_seal: Seal
    ) -> None:
        await _store_one(temp_storage, temp_seal)
        signing_key, _ = temp_seal._ensure_keys()

        def older_writer(model: CapsuleModel, data: dict) -> None:
            del data["spec_version"]
            model.hash = _sha3(data)
            model.signature = signing_key.sign(model.hash.encode("utf-8")).signature.hex()

        await _rewrite_stored(temp_storage, older_writer)
        result = await CapsuleChain(temp_storage).verify(seal=temp_seal)
        assert result.valid, result.error

    @pytest.mark.asyncio
    async def test_key_injected_beside_sealed_content_is_caught(
        self, temp_storage: CapsuleStorage, temp_seal: Seal
    ) -> None:
        await _store_one(temp_storage, temp_seal)
        await _rewrite_stored(temp_storage, lambda model, data: data.update(injected="unsigned"))
        result = await CapsuleChain(temp_storage).verify(verify_content=True)
        assert result.valid is False
        assert result.error is not None and "hash mismatch" in result.error.lower()


class _FakeBegin:
    """An ``engine.begin()`` context whose connection runs ``run_sync`` through a hook."""

    def __init__(self, on_run_sync):
        self._on_run_sync = on_run_sync

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def run_sync(self, fn):
        self._on_run_sync()


class _FakeEngine:
    def __init__(self, on_run_sync):
        self._on_run_sync = on_run_sync
        self.disposed = 0

    def begin(self):
        return _FakeBegin(self._on_run_sync)

    async def dispose(self):
        self.disposed += 1


class TestStorageInitialization:
    @pytest.mark.asyncio
    async def test_failed_schema_creation_disposes_the_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse() -> None:
            raise RuntimeError("disk full")

        engine = _FakeEngine(refuse)
        monkeypatch.setattr("qp_capsule.storage.create_async_engine", lambda *a, **k: engine)
        storage = CapsuleStorage(db_path=tmp_path / "capsules.db")
        with pytest.raises(RuntimeError, match="disk full"):
            await storage._ensure_db()
        assert engine.disposed == 1
        assert storage._session_factory is None

    @pytest.mark.asyncio
    async def test_concurrent_initialization_keeps_the_first_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        storage = CapsuleStorage(db_path=tmp_path / "capsules.db")
        winner = object()

        def another_caller_finishes_first() -> None:
            storage._session_factory = winner  # type: ignore[assignment]

        engine = _FakeEngine(another_caller_finishes_first)
        monkeypatch.setattr("qp_capsule.storage.create_async_engine", lambda *a, **k: engine)
        await storage._ensure_db()
        assert engine.disposed == 1
        assert storage._session_factory is winner
        assert storage._engine is None
