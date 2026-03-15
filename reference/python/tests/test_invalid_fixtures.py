"""
Tests for invalid capsule fixtures (conformance/invalid-fixtures.json).

Validates that malformed capsule structures, wrong types, invalid values,
chain violations, and tampered content are correctly detectable by the
Python reference implementation.
"""

import json
from pathlib import Path

import pytest

from qp_capsule.seal import compute_hash

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent
_FIXTURES_PATH = _REPO_ROOT / "conformance" / "invalid-fixtures.json"

_VALID_CATEGORIES = frozenset({
    "missing_field", "wrong_type", "invalid_value",
    "chain_violation", "integrity_violation",
})

_VALID_CAPSULE_TYPES = frozenset({
    "agent", "tool", "system", "kill", "workflow", "chat", "vault", "auth",
})

_REQUIRED_TOP_LEVEL = frozenset({
    "id", "type", "domain", "parent_id", "sequence", "previous_hash",
    "trigger", "context", "reasoning", "authority", "execution", "outcome",
})

_ALL_FIXTURE_NAMES = [
    "missing_id", "missing_type", "missing_trigger_section",
    "missing_reasoning_section", "sequence_wrong_type",
    "confidence_wrong_type", "trigger_type_null", "negative_sequence",
    "confidence_out_of_range", "unknown_capsule_type",
    "genesis_with_previous_hash", "non_genesis_null_previous_hash",
    "empty_object", "trigger_is_array", "tampered_content",
]


def _load():
    if not _FIXTURES_PATH.exists():
        pytest.skip(f"invalid-fixtures.json not found at {_FIXTURES_PATH}")
    return json.loads(_FIXTURES_PATH.read_text())["fixtures"]


@pytest.fixture(scope="module")
def fixtures():
    return _load()


@pytest.fixture(scope="module")
def by_name(fixtures):
    return {f["name"]: f for f in fixtures}


# ── Suite integrity ─────────────────────────────────────────────────


class TestSuiteIntegrity:
    def test_file_exists(self):
        assert _FIXTURES_PATH.exists()

    def test_has_15_fixtures(self, fixtures):
        assert len(fixtures) == 15

    def test_all_have_required_keys(self, fixtures):
        for f in fixtures:
            for key in ("name", "description", "expected_error", "capsule_dict"):
                assert key in f, f"fixture {f.get('name', '?')!r} missing {key!r}"

    def test_error_categories_valid(self, fixtures):
        for f in fixtures:
            assert f["expected_error"] in _VALID_CATEGORIES

    def test_names_unique(self, fixtures):
        names = [f["name"] for f in fixtures]
        assert len(names) == len(set(names))


# ── Missing fields ──────────────────────────────────────────────────


class TestMissingFields:
    def test_missing_id(self, by_name):
        assert "id" not in by_name["missing_id"]["capsule_dict"]

    def test_missing_type(self, by_name):
        assert "type" not in by_name["missing_type"]["capsule_dict"]

    def test_missing_trigger_section(self, by_name):
        assert "trigger" not in by_name["missing_trigger_section"]["capsule_dict"]

    def test_missing_reasoning_section(self, by_name):
        assert "reasoning" not in by_name["missing_reasoning_section"]["capsule_dict"]

    def test_empty_object_has_no_keys(self, by_name):
        assert by_name["empty_object"]["capsule_dict"] == {}

    @pytest.mark.parametrize("name", [
        "missing_id", "missing_type", "missing_trigger_section",
        "missing_reasoning_section", "empty_object",
    ])
    def test_all_categorized_as_missing_field(self, by_name, name):
        assert by_name[name]["expected_error"] == "missing_field"

    @pytest.mark.parametrize("name", [
        "missing_id", "missing_type", "missing_trigger_section",
        "missing_reasoning_section",
    ])
    def test_remaining_fields_are_valid(self, by_name, name):
        """Missing-field fixtures should only omit the declared field."""
        d = by_name[name]["capsule_dict"]
        missing = by_name[name]["error_field"]
        present = set(d.keys())
        expected = _REQUIRED_TOP_LEVEL - {missing}
        assert present == expected


# ── Wrong types ─────────────────────────────────────────────────────


class TestWrongTypes:
    def test_sequence_is_string(self, by_name):
        assert isinstance(
            by_name["sequence_wrong_type"]["capsule_dict"]["sequence"], str
        )

    def test_confidence_is_string(self, by_name):
        r = by_name["confidence_wrong_type"]["capsule_dict"]["reasoning"]
        assert isinstance(r["confidence"], str)

    def test_trigger_type_is_null(self, by_name):
        assert by_name["trigger_type_null"]["capsule_dict"]["trigger"]["type"] is None

    def test_trigger_is_array(self, by_name):
        assert isinstance(
            by_name["trigger_is_array"]["capsule_dict"]["trigger"], list
        )


# ── Invalid values ──────────────────────────────────────────────────


class TestInvalidValues:
    def test_negative_sequence(self, by_name):
        assert by_name["negative_sequence"]["capsule_dict"]["sequence"] < 0

    def test_confidence_exceeds_one(self, by_name):
        c = by_name["confidence_out_of_range"]["capsule_dict"]["reasoning"]["confidence"]
        assert c > 1.0

    def test_unknown_capsule_type(self, by_name):
        t = by_name["unknown_capsule_type"]["capsule_dict"]["type"]
        assert t not in _VALID_CAPSULE_TYPES


# ── Chain violations ────────────────────────────────────────────────


class TestChainViolations:
    def test_genesis_with_previous_hash(self, by_name):
        d = by_name["genesis_with_previous_hash"]["capsule_dict"]
        assert d["sequence"] == 0
        assert d["previous_hash"] is not None
        assert len(d["previous_hash"]) == 64

    def test_non_genesis_null_previous_hash(self, by_name):
        d = by_name["non_genesis_null_previous_hash"]["capsule_dict"]
        assert d["sequence"] == 1
        assert d["previous_hash"] is None


# ── Integrity violation ─────────────────────────────────────────────


class TestIntegrityViolation:
    def test_tampered_content_detected(self, by_name):
        """compute_hash on tampered content must differ from the claimed hash."""
        f = by_name["tampered_content"]
        recomputed = compute_hash(f["capsule_dict"])
        assert recomputed != f["claimed_hash"]

    def test_tampered_field_is_domain(self, by_name):
        assert by_name["tampered_content"]["capsule_dict"]["domain"] == "tampered"

    def test_claimed_hash_is_minimal_fixture_hash(self, by_name):
        """The claimed hash should match the known minimal fixture hash."""
        f = by_name["tampered_content"]
        assert f["claimed_hash"] == (
            "e6266f6d907a02e1f3531dc354765c0bca506180b91c1f5892a544b81bcf8dee"
        )


# ── Coverage guard ──────────────────────────────────────────────────


class TestAllFixturesCovered:
    def test_every_expected_fixture_exists(self, by_name):
        for name in _ALL_FIXTURE_NAMES:
            assert name in by_name, f"missing fixture: {name}"

    def test_no_untested_fixtures(self, by_name):
        untested = set(by_name) - set(_ALL_FIXTURE_NAMES)
        assert not untested, f"untested fixtures: {untested}"
