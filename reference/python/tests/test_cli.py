"""
Tests for the capsule CLI.

Tests cover the CLI entry point, verification logic, inspection,
key management, and the hash utility.
"""

import json
import tempfile
from io import StringIO
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from qp_capsule.capsule import Capsule, TriggerSection
from qp_capsule.cli import (
    VerifyError,
    VerifyResult,
    _build_parser,
    _capsule_from_full_dict,
    _capsule_to_full_dict,
    _load_capsules_from_json,
    _supports_color,
    cmd_hash,
    cmd_inspect,
    cmd_keys,
    cmd_verify,
    main,
    verify_chain,
)
from qp_capsule.keyring import Keyring
from qp_capsule.seal import Seal


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def key_path(temp_dir):
    return temp_dir / "key"


@pytest.fixture
def keyring_path(temp_dir):
    return temp_dir / "keyring.json"


@pytest.fixture
def seal(key_path):
    return Seal(key_path=key_path)


def _make_sealed_chain(seal: Seal, count: int) -> list[Capsule]:
    """Create a sealed chain of capsules."""
    capsules: list[Capsule] = []
    for i in range(count):
        c = Capsule(trigger=TriggerSection(type="test", source="test-cli", request=f"req_{i}"))
        c.sequence = i
        c.previous_hash = capsules[-1].hash if capsules else None
        seal.seal(c)
        capsules.append(c)
    return capsules


def _write_chain_json(capsules: list[Capsule], path: Path) -> Path:
    """Write a sealed chain to a JSON file."""
    data = [_capsule_to_full_dict(c) for c in capsules]
    path.write_text(json.dumps(data, indent=2))
    return path


# ---------------------------------------------------------------------------
# VerifyResult / VerifyError serialization
# ---------------------------------------------------------------------------


class TestVerifyResult:
    def test_to_dict(self):
        r = VerifyResult(valid=True, level="structural", capsules_verified=3, total_capsules=3)
        d = r.to_dict()
        assert d["valid"] is True
        assert d["capsules_verified"] == 3

    def test_with_errors(self):
        err = VerifyError(sequence=2, capsule_id="abc", error="broken")
        r = VerifyResult(
            valid=False, level="full", capsules_verified=2, total_capsules=5, errors=[err]
        )
        d = r.to_dict()
        assert d["valid"] is False
        assert len(d["errors"]) == 1
        assert d["errors"][0]["sequence"] == 2


# ---------------------------------------------------------------------------
# Capsule dict helpers
# ---------------------------------------------------------------------------


class TestCapsuleDictHelpers:
    def test_roundtrip(self, seal):
        c = Capsule(trigger=TriggerSection(type="test", source="s", request="r"))
        c.sequence = 0
        c.previous_hash = None
        seal.seal(c)

        d = _capsule_to_full_dict(c)
        restored = _capsule_from_full_dict(d)

        assert str(restored.id) == str(c.id)
        assert restored.hash == c.hash
        assert restored.signature == c.signature
        assert restored.signed_by == c.signed_by

    def test_from_dict_without_seal_fields(self):
        d = Capsule().to_dict()
        c = _capsule_from_full_dict(d)
        assert c.hash == ""
        assert c.signature == ""
        assert c.signed_by == ""


# ---------------------------------------------------------------------------
# JSON loading
# ---------------------------------------------------------------------------


class TestLoadFromJson:
    def test_load_array(self, seal, temp_dir):
        chain = _make_sealed_chain(seal, 3)
        path = _write_chain_json(chain, temp_dir / "chain.json")
        loaded = _load_capsules_from_json(path)
        assert len(loaded) == 3
        assert loaded[0].hash == chain[0].hash

    def test_load_single_object(self, seal, temp_dir):
        chain = _make_sealed_chain(seal, 1)
        d = _capsule_to_full_dict(chain[0])
        path = temp_dir / "single.json"
        path.write_text(json.dumps(d))
        loaded = _load_capsules_from_json(path)
        assert len(loaded) == 1

    def test_load_invalid_json_type(self, temp_dir):
        path = temp_dir / "bad.json"
        path.write_text('"just a string"')
        with pytest.raises(ValueError, match="Expected JSON array"):
            _load_capsules_from_json(path)


# ---------------------------------------------------------------------------
# Core verification logic
# ---------------------------------------------------------------------------


class TestVerifyChain:
    def test_empty_chain(self):
        r = verify_chain([])
        assert r.valid is True
        assert r.capsules_verified == 0

    def test_valid_structural(self, seal):
        chain = _make_sealed_chain(seal, 5)
        r = verify_chain(chain, level="structural")
        assert r.valid is True
        assert r.capsules_verified == 5

    def test_valid_full(self, seal):
        chain = _make_sealed_chain(seal, 3)
        r = verify_chain(chain, level="full")
        assert r.valid is True

    def test_valid_signatures(self, seal):
        chain = _make_sealed_chain(seal, 3)
        r = verify_chain(chain, level="signatures", seal=seal)
        assert r.valid is True

    def test_sequence_gap(self, seal):
        chain = _make_sealed_chain(seal, 3)
        chain[1].sequence = 5
        r = verify_chain(chain, level="structural")
        assert r.valid is False
        assert r.capsules_verified == 1
        assert "Sequence gap" in r.errors[0].error

    def test_genesis_with_previous_hash(self, seal):
        chain = _make_sealed_chain(seal, 1)
        chain[0].previous_hash = "should_be_none"
        r = verify_chain(chain, level="structural")
        assert r.valid is False
        assert "Genesis" in r.errors[0].error

    def test_broken_previous_hash(self, seal):
        chain = _make_sealed_chain(seal, 3)
        chain[2].previous_hash = "wrong"
        r = verify_chain(chain, level="structural")
        assert r.valid is False
        assert r.capsules_verified == 2

    def test_content_hash_mismatch(self, seal):
        chain = _make_sealed_chain(seal, 3)
        chain[1].trigger.request = "tampered"
        r = verify_chain(chain, level="full")
        assert r.valid is False
        assert "hash mismatch" in r.errors[0].error

    def test_signature_failure(self, seal, key_path):
        chain = _make_sealed_chain(seal, 2)
        chain[0].signature = "00" * 64
        r = verify_chain(chain, level="signatures", seal=seal)
        assert r.valid is False
        assert "Signature" in r.errors[0].error


# ---------------------------------------------------------------------------
# cmd_verify
# ---------------------------------------------------------------------------


class TestCmdVerify:
    def test_verify_json_structural(self, seal, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 3)
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", str(path)])
        assert cmd_verify(args) == 0

    def test_verify_json_full(self, seal, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 3)
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", "--full", str(path)])
        assert cmd_verify(args) == 0

    def test_verify_json_output(self, seal, temp_dir, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 2)
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", "--json", str(path)])
        assert cmd_verify(args) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["valid"] is True

    def test_verify_quiet_pass(self, seal, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 2)
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", "--quiet", str(path)])
        assert cmd_verify(args) == 0

    def test_verify_quiet_fail(self, seal, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 2)
        chain[1].previous_hash = "bad"
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", "--quiet", str(path)])
        assert cmd_verify(args) == 1

    def test_verify_no_source(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        args = _build_parser().parse_args(["verify"])
        assert cmd_verify(args) == 2

    def test_verify_multiple_sources(self, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        path = temp_dir / "c.json"
        path.write_text("[]")
        args = _build_parser().parse_args(["verify", str(path), "--db", "other.db"])
        assert cmd_verify(args) == 2

    def test_verify_bad_file(self, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        args = _build_parser().parse_args(["verify", str(temp_dir / "nonexistent.json")])
        assert cmd_verify(args) == 2

    def test_verify_broken_chain_colored(self, seal, temp_dir, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 3)
        chain[1].previous_hash = "wrong"
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", str(path)])
        result = cmd_verify(args)
        assert result == 1
        out = capsys.readouterr().out
        assert "FAIL" in out

    def test_verify_db_structural(self, seal, temp_dir, monkeypatch):
        """Verify from SQLite database."""
        monkeypatch.setenv("NO_COLOR", "1")

        async def _setup_db():
            from qp_capsule.storage import CapsuleStorage

            db_path = temp_dir / "test.db"
            storage = CapsuleStorage(db_path=db_path)
            for i in range(3):
                c = Capsule(
                    trigger=TriggerSection(type="test", source="db-test", request=f"r{i}")
                )
                c.sequence = i
                c.previous_hash = None
                if i > 0:
                    latest = await storage.get_latest()
                    c.previous_hash = latest.hash if latest else None
                seal.seal(c)
                await storage.store(c)
            await storage.close()
            return db_path

        import asyncio

        db_path = asyncio.run(_setup_db())
        args = _build_parser().parse_args(["verify", "--db", str(db_path)])
        assert cmd_verify(args) == 0

    def test_verify_full_json_broken(self, seal, temp_dir, capsys, monkeypatch):
        """--full --json on a broken chain produces structured error output."""
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 3)
        chain[1].trigger.request = "tampered"
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", "--full", "--json", str(path)])
        assert cmd_verify(args) == 1
        out = json.loads(capsys.readouterr().out)
        assert out["valid"] is False
        assert len(out["errors"]) == 1
        assert "hash mismatch" in out["errors"][0]["error"]

    def test_verify_colored_shows_skipped_capsules(self, seal, temp_dir, capsys, monkeypatch):
        """Colored output shows skipped capsules beyond the break point."""
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 5)
        chain[2].previous_hash = "broken"
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", str(path)])
        cmd_verify(args)
        out = capsys.readouterr().out
        assert "skipped" in out

    def test_verify_signatures_with_keyring(self, temp_dir, monkeypatch):
        """Signature verification using keyring via QUANTUMPIPES_DATA_DIR."""
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(temp_dir))

        key_path = temp_dir / "key"
        kr = Keyring(keyring_path=temp_dir / "keyring.json", key_path=key_path)
        seal_obj = Seal(key_path=key_path, keyring=kr)

        chain = _make_sealed_chain(seal_obj, 3)
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", "--signatures", str(path)])
        assert cmd_verify(args) == 0


# ---------------------------------------------------------------------------
# cmd_inspect
# ---------------------------------------------------------------------------


class TestCmdInspect:
    def test_inspect_single_json(self, seal, temp_dir, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 1)
        d = _capsule_to_full_dict(chain[0])
        path = temp_dir / "single.json"
        path.write_text(json.dumps(d))

        args = _build_parser().parse_args(["inspect", str(path)])
        assert cmd_inspect(args) == 0
        out = capsys.readouterr().out
        assert "Capsule Inspection" in out
        assert "Trigger" in out
        assert "Outcome" in out

    def test_inspect_by_seq(self, seal, temp_dir, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 5)
        path = _write_chain_json(chain, temp_dir / "chain.json")

        args = _build_parser().parse_args(["inspect", str(path), "--seq", "2"])
        assert cmd_inspect(args) == 0
        out = capsys.readouterr().out
        assert "Sequence: 2" in out

    def test_inspect_by_id(self, seal, temp_dir, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 3)
        target_id = str(chain[1].id)
        path = _write_chain_json(chain, temp_dir / "chain.json")

        args = _build_parser().parse_args(["inspect", str(path), "--id", target_id])
        assert cmd_inspect(args) == 0
        out = capsys.readouterr().out
        assert target_id in out

    def test_inspect_seq_not_found(self, seal, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 2)
        path = _write_chain_json(chain, temp_dir / "chain.json")

        args = _build_parser().parse_args(["inspect", str(path), "--seq", "99"])
        assert cmd_inspect(args) == 2

    def test_inspect_id_not_found(self, seal, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 2)
        path = _write_chain_json(chain, temp_dir / "chain.json")

        args = _build_parser().parse_args(["inspect", str(path), "--id", "nonexistent"])
        assert cmd_inspect(args) == 2

    def test_inspect_ambiguous_no_selector(self, seal, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 3)
        path = _write_chain_json(chain, temp_dir / "chain.json")

        args = _build_parser().parse_args(["inspect", str(path)])
        assert cmd_inspect(args) == 2

    def test_inspect_no_source(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        args = _build_parser().parse_args(["inspect"])
        assert cmd_inspect(args) == 2

    def test_inspect_bad_file(self, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        args = _build_parser().parse_args(["inspect", str(temp_dir / "gone.json")])
        assert cmd_inspect(args) == 2

    def test_inspect_with_outcome_error(self, seal, temp_dir, capsys, monkeypatch):
        """Inspect prints the error field when outcome has an error."""
        monkeypatch.setenv("NO_COLOR", "1")
        c = Capsule(trigger=TriggerSection(type="test", source="s", request="r"))
        c.sequence = 0
        c.previous_hash = None
        c.outcome.status = "failure"
        c.outcome.error = "something went wrong"
        seal.seal(c)
        d = _capsule_to_full_dict(c)
        path = temp_dir / "err.json"
        path.write_text(json.dumps(d))

        args = _build_parser().parse_args(["inspect", str(path)])
        assert cmd_inspect(args) == 0
        out = capsys.readouterr().out
        assert "something went wrong" in out

    def test_inspect_from_db_by_id(self, seal, temp_dir, capsys, monkeypatch):
        """Inspect a capsule from SQLite by ID."""
        monkeypatch.setenv("NO_COLOR", "1")

        async def _setup_db():
            from qp_capsule.storage import CapsuleStorage

            db_path = temp_dir / "inspect.db"
            storage = CapsuleStorage(db_path=db_path)
            c = Capsule(trigger=TriggerSection(type="test", source="db", request="check"))
            c.sequence = 0
            c.previous_hash = None
            seal.seal(c)
            await storage.store(c)
            await storage.close()
            return db_path, str(c.id)

        import asyncio

        db_path, cid = asyncio.run(_setup_db())
        args = _build_parser().parse_args(["inspect", "--db", str(db_path), "--id", cid])
        assert cmd_inspect(args) == 0
        out = capsys.readouterr().out
        assert "Capsule Inspection" in out

    def test_inspect_from_db_by_seq(self, seal, temp_dir, capsys, monkeypatch):
        """Inspect a capsule from SQLite by sequence number."""
        monkeypatch.setenv("NO_COLOR", "1")

        async def _setup_db():
            from qp_capsule.storage import CapsuleStorage

            db_path = temp_dir / "inspect_seq.db"
            storage = CapsuleStorage(db_path=db_path)
            for i in range(3):
                c = Capsule(
                    trigger=TriggerSection(type="test", source="db", request=f"seq{i}")
                )
                c.sequence = i
                c.previous_hash = None
                if i > 0:
                    latest = await storage.get_latest()
                    c.previous_hash = latest.hash if latest else None
                seal.seal(c)
                await storage.store(c)
            await storage.close()
            return db_path

        import asyncio

        db_path = asyncio.run(_setup_db())
        args = _build_parser().parse_args(["inspect", "--db", str(db_path), "--seq", "1"])
        assert cmd_inspect(args) == 0
        out = capsys.readouterr().out
        assert "Sequence: 1" in out


# ---------------------------------------------------------------------------
# cmd_keys
# ---------------------------------------------------------------------------


class TestCmdKeys:
    def test_keys_info_empty(self, keyring_path, key_path, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(keyring_path.parent))

        args = _build_parser().parse_args(["keys", "info"])
        assert cmd_keys(args) == 0
        out = capsys.readouterr().out
        assert "No keys" in out

    def test_keys_info_with_epochs(self, key_path, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(key_path.parent))

        sk = SigningKey.generate()
        key_path.write_bytes(bytes(sk))

        args = _build_parser().parse_args(["keys", "info"])
        assert cmd_keys(args) == 0
        out = capsys.readouterr().out
        assert "Epoch 0" in out
        assert "active" in out

    def test_keys_rotate(self, key_path, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(key_path.parent))

        args = _build_parser().parse_args(["keys", "rotate"])
        assert cmd_keys(args) == 0
        out = capsys.readouterr().out
        assert "Rotation" in out
        assert "active" in out

    def test_keys_rotate_with_existing(self, key_path, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(key_path.parent))

        sk = SigningKey.generate()
        key_path.write_bytes(bytes(sk))

        args = _build_parser().parse_args(["keys", "rotate"])
        assert cmd_keys(args) == 0
        out = capsys.readouterr().out
        assert "retired" in out

    def test_keys_export(self, key_path, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(key_path.parent))

        sk = SigningKey.generate()
        key_path.write_bytes(bytes(sk))

        args = _build_parser().parse_args(["keys", "export-public"])
        assert cmd_keys(args) == 0
        out = capsys.readouterr().out.strip()
        assert len(out) == 64

    def test_keys_export_no_key(self, keyring_path, key_path, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(keyring_path.parent))

        args = _build_parser().parse_args(["keys", "export-public"])
        assert cmd_keys(args) == 2

    def test_keys_no_subcommand(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        args = _build_parser().parse_args(["keys"])
        assert cmd_keys(args) == 2


# ---------------------------------------------------------------------------
# cmd_hash
# ---------------------------------------------------------------------------


class TestCmdHash:
    def test_hash_file(self, temp_dir, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        path = temp_dir / "doc.txt"
        path.write_text("hello world")

        import hashlib

        expected = hashlib.sha3_256(b"hello world").hexdigest()

        args = _build_parser().parse_args(["hash", str(path)])
        assert cmd_hash(args) == 0
        out = capsys.readouterr().out.strip()
        assert out == expected

    def test_hash_missing_file(self, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        args = _build_parser().parse_args(["hash", str(temp_dir / "gone.txt")])
        assert cmd_hash(args) == 2


# ---------------------------------------------------------------------------
# main() integration
# ---------------------------------------------------------------------------


class TestMain:
    def test_no_command(self, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert main([]) == 2

    def test_version_flag(self, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        with pytest.raises(SystemExit, match="0"):
            main(["--version"])
        out = capsys.readouterr().out
        assert "capsule" in out
        assert "1.5.2" in out

    def test_verify_via_main(self, seal, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 2)
        path = _write_chain_json(chain, temp_dir / "c.json")
        assert main(["verify", "--quiet", str(path)]) == 0

    def test_hash_via_main(self, temp_dir, capsys, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        path = temp_dir / "f.bin"
        path.write_bytes(b"\x00\x01\x02")
        assert main(["hash", str(path)]) == 0


# ---------------------------------------------------------------------------
# ANSI color support detection
# ---------------------------------------------------------------------------


class TestDefaultKeyringPath:
    def test_default_keyring_path_without_env(self, monkeypatch):
        monkeypatch.delenv("QUANTUMPIPES_DATA_DIR", raising=False)
        from qp_capsule.paths import default_keyring_path

        p = default_keyring_path()
        assert str(p).endswith("keyring.json")
        assert ".quantumpipes" in str(p)


class TestColorSupport:
    def test_no_color_env(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert _supports_color(StringIO()) is False

    def test_force_color_env(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert _supports_color(StringIO()) is True

    def test_non_tty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        assert _supports_color(StringIO()) is False

    def test_ansi_no_color_passthrough(self):
        """_c() returns plain text when _NO_COLOR is True."""
        import qp_capsule.cli as cli_mod

        old = cli_mod._NO_COLOR
        cli_mod._NO_COLOR = True
        try:
            assert cli_mod._c("32", "hello") == "hello"
            assert cli_mod._green("ok") == "ok"
            assert cli_mod._red("err") == "err"
            assert cli_mod._bold("b") == "b"
            assert cli_mod._dim("d") == "d"
            assert cli_mod._yellow("y") == "y"
        finally:
            cli_mod._NO_COLOR = old


# ---------------------------------------------------------------------------
# Seal + Keyring integration via CLI
# ---------------------------------------------------------------------------


class TestVerifyOutput:
    """Test verify output formatting details."""

    def test_level_description_in_output(self, seal, temp_dir, capsys, monkeypatch):
        """Verify output includes the human-readable level description."""
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 2)
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", "--full", str(path)])
        cmd_verify(args)
        out = capsys.readouterr().out
        assert "SHA3-256 recomputation" in out

    def test_structural_description_in_output(self, seal, temp_dir, capsys, monkeypatch):
        """Default structural level shows its description."""
        monkeypatch.setenv("NO_COLOR", "1")
        chain = _make_sealed_chain(seal, 1)
        path = _write_chain_json(chain, temp_dir / "c.json")

        args = _build_parser().parse_args(["verify", str(path)])
        cmd_verify(args)
        out = capsys.readouterr().out
        assert "sequence + hash linkage" in out

    def test_empty_chain_json(self, temp_dir, capsys, monkeypatch):
        """--json on an empty chain produces valid JSON with 0 capsules."""
        monkeypatch.setenv("NO_COLOR", "1")
        path = temp_dir / "empty.json"
        path.write_text("[]")

        args = _build_parser().parse_args(["verify", "--json", str(path)])
        assert cmd_verify(args) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["valid"] is True
        assert out["capsules_verified"] == 0
        assert out["total_capsules"] == 0

    def test_signatures_without_seal_skips_sigs(self, seal):
        """verify_chain(level='signatures') without seal= skips signature checks gracefully."""
        chain = _make_sealed_chain(seal, 3)
        r = verify_chain(chain, level="signatures", seal=None)
        assert r.valid is True
        assert r.capsules_verified == 3


class TestKeyringVerification:
    """Test that signature verification works across key rotations."""

    def test_verify_with_keyring(self, temp_dir, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        key_path = temp_dir / "key"
        kr_path = temp_dir / "keyring.json"

        kr = Keyring(keyring_path=kr_path, key_path=key_path)
        seal_obj = Seal(key_path=key_path, keyring=kr)

        chain = _make_sealed_chain(seal_obj, 3)

        r = verify_chain(chain, level="signatures", seal=seal_obj)
        assert r.valid is True

    def test_verify_across_rotation(self, temp_dir, monkeypatch):
        """Capsules signed with old key verify after rotation."""
        monkeypatch.setenv("NO_COLOR", "1")
        key_path = temp_dir / "key"
        kr_path = temp_dir / "keyring.json"

        kr = Keyring(keyring_path=kr_path, key_path=key_path)
        seal_obj = Seal(key_path=key_path, keyring=kr)

        c0 = Capsule(trigger=TriggerSection(type="test", source="s", request="before rotation"))
        c0.sequence = 0
        c0.previous_hash = None
        seal_obj.seal(c0)

        kr.rotate()

        seal_obj2 = Seal(key_path=key_path, keyring=kr)

        c1 = Capsule(trigger=TriggerSection(type="test", source="s", request="after rotation"))
        c1.sequence = 1
        c1.previous_hash = c0.hash
        seal_obj2.seal(c1)

        r = verify_chain([c0, c1], level="signatures", seal=seal_obj2)
        assert r.valid is True
        assert r.capsules_verified == 2
