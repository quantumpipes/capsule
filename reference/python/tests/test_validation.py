"""
Tests for validate_capsule_dict / validate_capsule (FR-002).

Uses conformance/invalid-fixtures.json and golden vectors.
"""

import copy
import json
from pathlib import Path
from uuid import uuid4

import pytest

from qp_capsule.capsule import Capsule, CapsuleType
from qp_capsule.validation import (
    CapsuleValidationResult,
    validate_capsule,
    validate_capsule_dict,
)

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent
_INVALID_PATH = _REPO_ROOT / "conformance" / "invalid-fixtures.json"
_GOLDEN_PATH = _REPO_ROOT / "conformance" / "fixtures.json"


def _invalid_fixtures():
    data = json.loads(_INVALID_PATH.read_text())
    return data["fixtures"]


@pytest.fixture(scope="module")
def invalid_fixtures():
    return _invalid_fixtures()


@pytest.mark.parametrize("fixture", _invalid_fixtures(), ids=lambda f: f["name"])
def test_invalid_vectors_rejected(fixture):
    d = fixture["capsule_dict"]
    claimed = fixture.get("claimed_hash")
    r = validate_capsule_dict(d, claimed_hash=claimed)
    assert not r.ok, f"expected failure for {fixture['name']}: {r}"
    assert r.category == fixture["expected_error"], fixture["name"]
    assert r.field == fixture["error_field"], fixture["name"]


def test_golden_fixtures_accepted():
    data = json.loads(_GOLDEN_PATH.read_text())
    for f in data["fixtures"]:
        r = validate_capsule_dict(f["capsule_dict"])
        assert r.ok, f"{f['name']}: {r.message}"


def test_validate_capsule_round_trip():
    c = Capsule.create(capsule_type=CapsuleType.AGENT)
    c.id = uuid4()
    r = validate_capsule(c)
    assert r.ok


def test_validate_capsule_rejects_non_capsule():
    r = validate_capsule({"not": "a capsule"})
    assert not r.ok
    assert r.category == "wrong_type"


def test_strict_unknown_keys():
    d = json.loads(_GOLDEN_PATH.read_text())["fixtures"][0]["capsule_dict"]
    d2 = dict(d)
    d2["extra_top"] = 1
    r = validate_capsule_dict(d2, strict_unknown_keys=True)
    assert not r.ok
    assert r.field == "extra_top"


def test_claimed_hash_invalid_hex():
    d = json.loads(_GOLDEN_PATH.read_text())["fixtures"][0]["capsule_dict"]
    r = validate_capsule_dict(d, claimed_hash="not_hex")
    assert not r.ok
    assert r.field == "hash"


def test_root_not_object():
    r = validate_capsule_dict([])
    assert not r.ok
    assert r.category == "wrong_type"
    assert r.field == ""


def _minimal_golden() -> dict:
    data = json.loads(_GOLDEN_PATH.read_text())
    for f in data["fixtures"]:
        if f["name"] == "minimal":
            return copy.deepcopy(f["capsule_dict"])
    raise RuntimeError("minimal fixture missing")


class TestValidationBranches:
    """Cover branches not exercised by invalid-fixtures.json alone."""

    def test_id_wrong_type(self):
        d = _minimal_golden()
        d["id"] = 1
        r = validate_capsule_dict(d)
        assert r.category == "wrong_type"
        assert r.field == "id"

    def test_id_invalid_uuid_string(self):
        d = _minimal_golden()
        d["id"] = "not-a-uuid"
        r = validate_capsule_dict(d)
        assert r.category == "invalid_value"

    def test_type_wrong_type(self):
        d = _minimal_golden()
        d["type"] = 1
        r = validate_capsule_dict(d)
        assert r.field == "type"
        assert r.category == "wrong_type"

    def test_domain_wrong_type(self):
        d = _minimal_golden()
        d["domain"] = 1
        r = validate_capsule_dict(d)
        assert r.field == "domain"

    def test_parent_id_wrong_type(self):
        d = _minimal_golden()
        d["parent_id"] = 1
        r = validate_capsule_dict(d)
        assert r.field == "parent_id"
        assert r.category == "wrong_type"

    def test_parent_id_invalid_uuid(self):
        d = _minimal_golden()
        d["parent_id"] = "not-a-uuid"
        r = validate_capsule_dict(d)
        assert r.field == "parent_id"
        assert r.category == "invalid_value"

    def test_sequence_float_not_int(self):
        d = _minimal_golden()
        d["sequence"] = 0.0
        r = validate_capsule_dict(d)
        assert r.field == "sequence"
        assert r.category == "wrong_type"

    def test_previous_hash_wrong_type(self):
        d = _minimal_golden()
        d["previous_hash"] = 1
        r = validate_capsule_dict(d)
        assert r.field == "previous_hash"
        assert r.category == "wrong_type"

    def test_previous_hash_bad_hex_length(self):
        d = _minimal_golden()
        d["previous_hash"] = "aa"
        r = validate_capsule_dict(d)
        assert r.field == "previous_hash"
        assert r.category == "invalid_value"

    def test_spec_version_wrong_type(self):
        d = _minimal_golden()
        d["spec_version"] = 1
        r = validate_capsule_dict(d)
        assert r.field == "spec_version"
        assert r.category == "wrong_type"

    def test_spec_version_empty(self):
        d = _minimal_golden()
        d["spec_version"] = ""
        r = validate_capsule_dict(d)
        assert r.field == "spec_version"
        assert r.category == "invalid_value"

    def test_trigger_missing_subkey(self):
        d = _minimal_golden()
        del d["trigger"]["timestamp"]
        r = validate_capsule_dict(d)
        assert "trigger.timestamp" in r.field

    def test_trigger_timestamp_naive(self):
        d = _minimal_golden()
        d["trigger"]["timestamp"] = "2026-01-15T12:00:00"
        r = validate_capsule_dict(d)
        assert r.field == "trigger.timestamp"
        assert r.category == "invalid_value"

    def test_trigger_timestamp_wrong_type(self):
        d = _minimal_golden()
        d["trigger"]["timestamp"] = 1
        r = validate_capsule_dict(d)
        assert r.field == "trigger.timestamp"
        assert r.category == "wrong_type"

    def test_context_wrong_type(self):
        d = _minimal_golden()
        d["context"] = []
        r = validate_capsule_dict(d)
        assert r.field == "context"

    def test_context_missing_subkey(self):
        d = _minimal_golden()
        del d["context"]["agent_id"]
        r = validate_capsule_dict(d)
        assert r.field == "context.agent_id"

    def test_context_environment_wrong_type(self):
        d = _minimal_golden()
        d["context"]["environment"] = []
        r = validate_capsule_dict(d)
        assert r.field == "context.environment"

    def test_reasoning_wrong_type(self):
        d = _minimal_golden()
        d["reasoning"] = []
        r = validate_capsule_dict(d)
        assert r.field == "reasoning"

    def test_reasoning_missing_subkey(self):
        d = _minimal_golden()
        del d["reasoning"]["analysis"]
        r = validate_capsule_dict(d)
        assert r.field == "reasoning.analysis"

    def test_confidence_bool_rejected(self):
        d = _minimal_golden()
        d["reasoning"]["confidence"] = True
        r = validate_capsule_dict(d)
        assert r.field == "reasoning.confidence"

    def test_authority_wrong_type(self):
        d = _minimal_golden()
        d["authority"] = []
        r = validate_capsule_dict(d)
        assert r.field == "authority"

    def test_authority_missing_subkey(self):
        d = _minimal_golden()
        del d["authority"]["type"]
        r = validate_capsule_dict(d)
        assert r.field == "authority.type"

    def test_execution_wrong_type(self):
        d = _minimal_golden()
        d["execution"] = []
        r = validate_capsule_dict(d)
        assert r.field == "execution"

    def test_execution_missing_subkey(self):
        d = _minimal_golden()
        del d["execution"]["tool_calls"]
        r = validate_capsule_dict(d)
        assert r.field == "execution.tool_calls"

    def test_tool_calls_wrong_type(self):
        d = _minimal_golden()
        d["execution"]["tool_calls"] = {}
        r = validate_capsule_dict(d)
        assert r.field == "execution.tool_calls"

    def test_duration_ms_wrong_type(self):
        d = _minimal_golden()
        d["execution"]["duration_ms"] = 0.0
        r = validate_capsule_dict(d)
        assert r.field == "execution.duration_ms"

    def test_resources_used_wrong_type(self):
        d = _minimal_golden()
        d["execution"]["resources_used"] = []
        r = validate_capsule_dict(d)
        assert r.field == "execution.resources_used"

    def test_outcome_wrong_type(self):
        d = _minimal_golden()
        d["outcome"] = []
        r = validate_capsule_dict(d)
        assert r.field == "outcome"

    def test_outcome_missing_subkey(self):
        d = _minimal_golden()
        del d["outcome"]["status"]
        r = validate_capsule_dict(d)
        assert r.field == "outcome.status"

    def test_parse_iso8601_invalid_string(self):
        d = _minimal_golden()
        d["trigger"]["timestamp"] = "not-a-date"
        r = validate_capsule_dict(d)
        assert r.field == "trigger.timestamp"
        assert r.category == "invalid_value"

    def test_capsule_validation_result_success_factory(self):
        r = CapsuleValidationResult.success()
        assert r.ok and r.category is None

    def test_capsule_validation_result_fail_factory(self):
        r = CapsuleValidationResult.fail("invalid_value", "field", "msg")
        assert not r.ok
        assert r.category == "invalid_value"
        assert r.field == "field"
        assert r.message == "msg"
