# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""
Protocol repository structure tests.

Guards the protocol-first layout: spec at root, conformance suite prominent,
reference implementations in subdirectories, no pyproject.toml at repo root.
Any regression back toward "Python package" structure fails these tests.
"""

import json
import re
from pathlib import Path

import pytest

PYTHON_ROOT = Path(__file__).parent.parent
REPO_ROOT = PYTHON_ROOT.parent.parent


# ---------------------------------------------------------------------------
# Protocol-first layout: the repo must NOT look like a Python package
# ---------------------------------------------------------------------------


class TestProtocolFirstLayout:
    """The repo root must present as a protocol, not a Python package."""

    def test_no_pyproject_at_repo_root(self):
        """pyproject.toml belongs in reference/python/, not the repo root."""
        assert not (REPO_ROOT / "pyproject.toml").exists()

    def test_no_src_at_repo_root(self):
        """src/ belongs in reference/python/, not the repo root."""
        assert not (REPO_ROOT / "src").exists()

    def test_no_tests_at_repo_root(self):
        """tests/ belongs in reference/python/, not the repo root."""
        assert not (REPO_ROOT / "tests").exists()

    def test_no_setup_py_at_repo_root(self):
        assert not (REPO_ROOT / "setup.py").exists()

    def test_no_setup_cfg_at_repo_root(self):
        assert not (REPO_ROOT / "setup.cfg").exists()

    def test_spec_directory_exists(self):
        assert (REPO_ROOT / "spec").is_dir()

    def test_conformance_directory_exists(self):
        assert (REPO_ROOT / "conformance").is_dir()

    def test_reference_directory_exists(self):
        assert (REPO_ROOT / "reference").is_dir()

    def test_docs_directory_exists(self):
        assert (REPO_ROOT / "docs").is_dir()

    def test_examples_directory_exists(self):
        assert (REPO_ROOT / "examples").is_dir()


# ---------------------------------------------------------------------------
# Spec directory: the normative protocol specification
# ---------------------------------------------------------------------------


class TestSpecDirectory:
    """The spec/ directory contains the normative CPS specification."""

    def test_spec_readme_exists(self):
        assert (REPO_ROOT / "spec" / "README.md").exists()

    def test_uri_scheme_exists(self):
        assert (REPO_ROOT / "spec" / "uri-scheme.md").exists()

    def test_spec_readme_contains_version(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Version" in text
        assert "1.0" in text

    def test_spec_defines_six_sections(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        for section in ["trigger", "context", "reasoning", "authority", "execution", "outcome"]:
            assert section in text.lower(), f"Section '{section}' not found in spec"

    def test_spec_defines_canonical_json_rules(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Canonical JSON" in text

    def test_spec_defines_sealing_algorithm(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "SHA3-256" in text
        assert "Ed25519" in text

    def test_spec_defines_hash_chain(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "previous_hash" in text
        assert "sequence" in text

    def test_spec_has_security_considerations(self):
        """CPS spec must include a Security Considerations section."""
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Security Considerations" in text

    def test_spec_security_covers_key_compromise(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Key Compromise" in text or "Signer Key Compromise" in text

    def test_spec_security_covers_chain_truncation(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Chain Truncation" in text

    def test_spec_security_covers_verification_levels(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Verification Levels" in text or "verify_content" in text

    def test_spec_security_documents_non_goals(self):
        """Spec must be explicit about what CPS does NOT provide."""
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Does Not Provide" in text

    def test_spec_security_covers_timestamp_trust(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Timestamp" in text and "trust" in text.lower()

    def test_spec_security_covers_replay(self):
        text = (REPO_ROOT / "spec" / "README.md").read_text()
        assert "Replay" in text

    def test_uri_scheme_defines_capsule_protocol(self):
        text = (REPO_ROOT / "spec" / "uri-scheme.md").read_text()
        assert "capsule://" in text

    def test_uri_scheme_defines_hash_ref(self):
        text = (REPO_ROOT / "spec" / "uri-scheme.md").read_text()
        assert "sha3_" in text

    def test_uri_scheme_defines_fragment_syntax(self):
        text = (REPO_ROOT / "spec" / "uri-scheme.md").read_text()
        assert "#reasoning" in text or "fragment" in text.lower()

    def test_uri_scheme_has_security_considerations(self):
        text = (REPO_ROOT / "spec" / "uri-scheme.md").read_text()
        assert "Security Considerations" in text

    def test_uri_scheme_addresses_injection(self):
        text = (REPO_ROOT / "spec" / "uri-scheme.md").read_text()
        assert "injection" in text.lower() or "sanitize" in text.lower()

    def test_uri_scheme_addresses_resolution_trust(self):
        text = (REPO_ROOT / "spec" / "uri-scheme.md").read_text()
        assert "trust" in text.lower() and "resolution" in text.lower()

    def test_uri_scheme_status_is_active(self):
        """URI scheme must be finalized, not Draft."""
        text = (REPO_ROOT / "spec" / "uri-scheme.md").read_text()
        assert "**Status**: Active" in text, "URI scheme spec is not Active"
        assert "**Status**: Draft" not in text, "URI scheme spec still marked Draft"

    def test_uri_scheme_version_not_draft(self):
        """Version line must not contain '(Draft)'."""
        text = (REPO_ROOT / "spec" / "uri-scheme.md").read_text()
        assert "(Draft)" not in text, "URI scheme version still contains (Draft)"


# ---------------------------------------------------------------------------
# Conformance suite: golden test vectors
# ---------------------------------------------------------------------------


class TestConformanceSuite:
    """The conformance/ directory is the cross-language contract."""

    def test_fixtures_json_exists(self):
        assert (REPO_ROOT / "conformance" / "fixtures.json").exists()

    def test_conformance_readme_exists(self):
        assert (REPO_ROOT / "conformance" / "README.md").exists()

    def test_generator_script_exists(self):
        assert (REPO_ROOT / "conformance" / "generate_fixtures.py").exists()

    def test_fixtures_have_required_fields(self):
        with open(REPO_ROOT / "conformance" / "fixtures.json") as f:
            data = json.load(f)
        for fixture in data["fixtures"]:
            assert "name" in fixture, "Fixture missing 'name'"
            assert "capsule_dict" in fixture, f"{fixture.get('name')}: missing 'capsule_dict'"
            assert "canonical_json" in fixture, f"{fixture.get('name')}: missing 'canonical_json'"
            assert "sha3_256_hash" in fixture, f"{fixture.get('name')}: missing 'sha3_256_hash'"

    def test_all_capsule_types_covered(self):
        """Golden fixtures must cover every CapsuleType in the spec."""
        with open(REPO_ROOT / "conformance" / "fixtures.json") as f:
            data = json.load(f)
        types_in_fixtures = set()
        for fixture in data["fixtures"]:
            capsule = fixture["capsule_dict"]
            types_in_fixtures.add(capsule["type"])
        expected = {"agent", "tool", "system", "kill", "workflow", "chat", "vault", "auth"}
        missing = expected - types_in_fixtures
        assert not missing, f"CapsuleTypes missing from fixtures: {missing}"

    def test_chain_fixtures_present(self):
        """Must have at least one genesis and one linked fixture."""
        with open(REPO_ROOT / "conformance" / "fixtures.json") as f:
            data = json.load(f)
        names = {f["name"] for f in data["fixtures"]}
        assert "chain_genesis" in names, "Missing chain_genesis fixture"
        assert "chain_linked" in names, "Missing chain_linked fixture"

    def test_vault_fixture_present(self):
        """Vault fixture must exist to cover all 8 CapsuleTypes."""
        with open(REPO_ROOT / "conformance" / "fixtures.json") as f:
            data = json.load(f)
        names = {f["name"] for f in data["fixtures"]}
        assert "vault_secret" in names, "Missing vault_secret fixture"

    def test_vault_fixture_semantics(self):
        """Vault fixture must use type=vault with appropriate domain and authority."""
        with open(REPO_ROOT / "conformance" / "fixtures.json") as f:
            data = json.load(f)
        vault = next(f for f in data["fixtures"] if f["name"] == "vault_secret")
        capsule = vault["capsule_dict"]
        assert capsule["type"] == "vault"
        assert capsule["domain"] == "secrets"
        assert capsule["trigger"]["type"] == "scheduled"
        assert capsule["authority"]["type"] == "policy"
        assert capsule["authority"]["policy_reference"] is not None


# ---------------------------------------------------------------------------
# URI conformance vectors
# ---------------------------------------------------------------------------


class TestURIConformanceVectors:
    """The uri-fixtures.json must be structurally valid and internally consistent."""

    @pytest.fixture()
    def uri_data(self) -> dict:
        with open(REPO_ROOT / "conformance" / "uri-fixtures.json") as f:
            return json.load(f)

    @pytest.fixture()
    def capsule_fixtures(self) -> dict:
        with open(REPO_ROOT / "conformance" / "fixtures.json") as f:
            return json.load(f)

    def test_uri_fixtures_file_exists(self):
        assert (REPO_ROOT / "conformance" / "uri-fixtures.json").exists()

    def test_has_valid_and_invalid_sections(self, uri_data: dict):
        assert "valid" in uri_data, "Missing 'valid' section"
        assert "invalid" in uri_data, "Missing 'invalid' section"
        assert len(uri_data["valid"]) > 0, "No valid URI vectors"
        assert len(uri_data["invalid"]) > 0, "No invalid URI vectors"

    def test_valid_entries_have_required_fields(self, uri_data: dict):
        required = {"name", "description", "uri", "expected"}
        for entry in uri_data["valid"]:
            missing = required - set(entry.keys())
            assert not missing, f"Valid entry '{entry.get('name')}' missing: {missing}"

    def test_valid_expected_has_parse_fields(self, uri_data: dict):
        parse_fields = {
            "scheme", "chain", "reference_type", "hash_algorithm",
            "hash_value", "sequence", "id", "fragment",
        }
        for entry in uri_data["valid"]:
            expected = entry["expected"]
            missing = parse_fields - set(expected.keys())
            assert not missing, (
                f"Valid entry '{entry['name']}' expected missing: {missing}"
            )

    def test_all_valid_uris_start_with_capsule_scheme(self, uri_data: dict):
        for entry in uri_data["valid"]:
            assert entry["uri"].startswith("capsule://"), (
                f"Valid URI '{entry['name']}' doesn't start with capsule://"
            )
            assert entry["expected"]["scheme"] == "capsule"

    def test_invalid_entries_have_required_fields(self, uri_data: dict):
        required = {"name", "description", "uri", "reason"}
        for entry in uri_data["invalid"]:
            missing = required - set(entry.keys())
            assert not missing, f"Invalid entry '{entry.get('name')}' missing: {missing}"

    def test_valid_names_are_unique(self, uri_data: dict):
        names = [e["name"] for e in uri_data["valid"]]
        assert len(names) == len(set(names)), "Duplicate valid URI vector names"

    def test_invalid_names_are_unique(self, uri_data: dict):
        names = [e["name"] for e in uri_data["invalid"]]
        assert len(names) == len(set(names)), "Duplicate invalid URI vector names"

    def test_hash_uris_reference_valid_sha3_hex(self, uri_data: dict):
        """Hash references in valid URIs must contain exactly 64 lowercase hex chars."""
        for entry in uri_data["valid"]:
            if entry["expected"]["reference_type"] == "hash":
                h = entry["expected"]["hash_value"]
                assert re.fullmatch(r"[0-9a-f]{64}", h), (
                    f"Invalid hash in '{entry['name']}': {h}"
                )

    def test_hash_uris_use_hashes_from_golden_fixtures(
        self, uri_data: dict, capsule_fixtures: dict,
    ):
        """Hash values in valid URI vectors should come from real golden fixtures."""
        golden_hashes = {
            f["sha3_256_hash"] for f in capsule_fixtures["fixtures"]
        }
        for entry in uri_data["valid"]:
            if entry["expected"]["reference_type"] == "hash":
                h = entry["expected"]["hash_value"]
                assert h in golden_hashes, (
                    f"URI vector '{entry['name']}' uses hash {h[:16]}... "
                    f"not found in golden fixtures"
                )

    def test_covers_all_reference_types(self, uri_data: dict):
        """Must have vectors for hash, sequence, and id reference types."""
        ref_types = {e["expected"]["reference_type"] for e in uri_data["valid"]}
        assert {"hash", "sequence", "id"} <= ref_types, (
            f"Missing reference types: { {'hash', 'sequence', 'id'} - ref_types}"
        )

    def test_covers_fragment_syntax(self, uri_data: dict):
        """At least one valid vector must include a fragment."""
        has_fragment = any(
            e["expected"]["fragment"] is not None for e in uri_data["valid"]
        )
        assert has_fragment, "No valid URI vectors test fragment syntax"

    def test_invalid_covers_common_attack_vectors(self, uri_data: dict):
        """Invalid vectors must cover injection, truncation, and traversal."""
        names = {e["name"] for e in uri_data["invalid"]}
        assert "hash_too_short" in names, "Missing truncated hash vector"
        assert "hash_too_long" in names, "Missing overlong hash vector"
        assert "fragment_traversal" in names, "Missing path traversal vector"
        assert "wrong_scheme" in names, "Missing wrong-scheme vector"
        assert "hash_uppercase" in names, "Missing uppercase hash vector"


# ---------------------------------------------------------------------------
# Reference implementations: multi-language presence
# ---------------------------------------------------------------------------


class TestReferenceImplementations:
    """At least Python + TypeScript skeleton must exist."""

    def test_python_reference_exists(self):
        assert (REPO_ROOT / "reference" / "python").is_dir()

    def test_python_has_pyproject(self):
        assert (REPO_ROOT / "reference" / "python" / "pyproject.toml").exists()

    def test_python_has_src(self):
        assert (REPO_ROOT / "reference" / "python" / "src" / "qp_capsule").is_dir()

    def test_python_has_tests(self):
        assert (REPO_ROOT / "reference" / "python" / "tests").is_dir()

    def test_python_has_readme(self):
        assert (REPO_ROOT / "reference" / "python" / "README.md").exists()

    def test_typescript_reference_exists(self):
        assert (REPO_ROOT / "reference" / "typescript").is_dir()

    def test_typescript_has_package_json(self):
        assert (REPO_ROOT / "reference" / "typescript" / "package.json").exists()

    def test_typescript_has_tsconfig(self):
        assert (REPO_ROOT / "reference" / "typescript" / "tsconfig.json").exists()

    def test_typescript_has_src(self):
        assert (REPO_ROOT / "reference" / "typescript" / "src" / "index.ts").exists()

    def test_typescript_has_readme(self):
        assert (REPO_ROOT / "reference" / "typescript" / "README.md").exists()

    def test_reference_readme_exists(self):
        assert (REPO_ROOT / "reference" / "README.md").exists()

    def test_reference_readme_has_status_matrix(self):
        text = (REPO_ROOT / "reference" / "README.md").read_text()
        assert "Python" in text
        assert "TypeScript" in text


# ---------------------------------------------------------------------------
# TypeScript type definitions: must match the CPS spec
# ---------------------------------------------------------------------------


class TestTypeScriptSpecAlignment:
    """TypeScript types must define all CapsuleTypes and sections from the spec."""

    @pytest.fixture()
    def ts_source(self) -> str:
        ts_dir = REPO_ROOT / "reference" / "typescript" / "src"
        parts = []
        for ts_file in sorted(ts_dir.glob("*.ts")):
            parts.append(ts_file.read_text())
        return "\n".join(parts)

    def test_all_capsule_types_defined(self, ts_source: str):
        for t in ["agent", "tool", "system", "kill", "workflow", "chat", "vault", "auth"]:
            assert f'"{t}"' in ts_source, f"CapsuleType '{t}' missing from TypeScript types"

    def test_all_sections_defined(self, ts_source: str):
        for section in [
            "TriggerSection",
            "ContextSection",
            "ReasoningSection",
            "AuthoritySection",
            "ExecutionSection",
            "OutcomeSection",
        ]:
            assert section in ts_source, f"Interface '{section}' missing from TypeScript types"

    def test_capsule_interface_defined(self, ts_source: str):
        assert "interface Capsule" in ts_source

    def test_seal_fields_defined(self, ts_source: str):
        assert "SealFields" in ts_source

    def test_canonicalize_exported(self, ts_source: str):
        assert "canonicalize" in ts_source

    def test_compute_hash_exported(self, ts_source: str):
        assert "computeHash" in ts_source

    def test_seal_function_exported(self, ts_source: str):
        assert "seal" in ts_source and "async function seal" in ts_source

    def test_verify_function_exported(self, ts_source: str):
        assert "verify" in ts_source and "async function verify" in ts_source

    def test_outcome_statuses_match_spec(self, ts_source: str):
        for status in ["pending", "success", "failure", "partial", "blocked"]:
            assert f'"{status}"' in ts_source, f"OutcomeStatus '{status}' missing"

    def test_authority_types_match_spec(self, ts_source: str):
        for auth_type in ["autonomous", "human_approved", "policy", "escalated"]:
            assert f'"{auth_type}"' in ts_source, f"AuthorityType '{auth_type}' missing"

    def test_trigger_types_match_spec(self, ts_source: str):
        for trigger in ["user_request", "scheduled", "system", "agent"]:
            assert f'"{trigger}"' in ts_source, f"TriggerType '{trigger}' missing"

    def test_noble_hashes_in_package_json(self):
        with open(REPO_ROOT / "reference" / "typescript" / "package.json") as f:
            pkg = json.load(f)
        deps = pkg.get("dependencies", {})
        assert "@noble/hashes" in deps, "@noble/hashes must be a dependency"
        assert "@noble/ed25519" in deps, "@noble/ed25519 must be a dependency"


# ---------------------------------------------------------------------------
# Protocol documentation: completeness
# ---------------------------------------------------------------------------


class TestProtocolDocs:
    """Protocol-level docs must exist and cover key topics."""

    REQUIRED_DOCS = [
        "README.md",
        "architecture.md",
        "security.md",
        "compliance.md",
        "why-capsules.md",
        "implementors-guide.md",
    ]

    @pytest.mark.parametrize("filename", REQUIRED_DOCS)
    def test_doc_exists(self, filename: str):
        assert (REPO_ROOT / "docs" / filename).exists(), f"docs/{filename} missing"

    def test_python_specific_docs_not_in_protocol_docs(self):
        """API reference and getting-started are Python-specific, not protocol-level."""
        protocol_docs = {p.name for p in (REPO_ROOT / "docs").glob("*.md")}
        python_only = {"api.md", "getting-started.md", "high-level-api.md"}
        misplaced = python_only & protocol_docs
        assert not misplaced, (
            f"Python-specific docs in protocol docs/: {misplaced} "
            f"— move to reference/python/docs/"
        )

    def test_python_docs_exist_in_reference(self):
        python_docs = REPO_ROOT / "reference" / "python" / "docs"
        assert (python_docs / "api.md").exists()
        assert (python_docs / "getting-started.md").exists()


# ---------------------------------------------------------------------------
# Markdown link integrity: internal links must resolve
# ---------------------------------------------------------------------------


class TestMarkdownLinks:
    """Internal markdown links must point to files that exist."""

    @staticmethod
    def _extract_md_links(path: Path) -> list[tuple[str, str]]:
        """Extract [text](target) links from a markdown file, excluding URLs."""
        text = path.read_text()
        links = re.findall(r"\[([^\]]*)\]\(([^)]+)\)", text)
        return [
            (label, target)
            for label, target in links
            if not target.startswith("http")
            and not target.startswith("#")
            and not target.startswith("mailto:")
        ]

    @staticmethod
    def _resolve_link(source: Path, target: str) -> Path:
        """Resolve a relative link from a markdown file."""
        clean = target.split("#")[0]
        return (source.parent / clean).resolve()

    def _check_links_in_dir(self, directory: Path) -> list[str]:
        broken = []
        for md_file in directory.glob("*.md"):
            for label, target in self._extract_md_links(md_file):
                resolved = self._resolve_link(md_file, target)
                if not resolved.exists():
                    broken.append(f"{md_file.relative_to(REPO_ROOT)}: [{label}]({target})")
        return broken

    def test_root_readme_links(self):
        broken = []
        for label, target in self._extract_md_links(REPO_ROOT / "README.md"):
            resolved = self._resolve_link(REPO_ROOT / "README.md", target)
            if not resolved.exists():
                broken.append(f"README.md: [{label}]({target})")
        assert not broken, "Broken links in README.md:\n" + "\n".join(broken)

    def test_spec_links(self):
        broken = self._check_links_in_dir(REPO_ROOT / "spec")
        assert not broken, "Broken links in spec/:\n" + "\n".join(broken)

    def test_docs_links(self):
        broken = self._check_links_in_dir(REPO_ROOT / "docs")
        assert not broken, "Broken links in docs/:\n" + "\n".join(broken)

    def test_conformance_links(self):
        broken = self._check_links_in_dir(REPO_ROOT / "conformance")
        assert not broken, "Broken links in conformance/:\n" + "\n".join(broken)

    def test_reference_readme_links(self):
        broken = []
        for label, target in self._extract_md_links(REPO_ROOT / "reference" / "README.md"):
            resolved = self._resolve_link(REPO_ROOT / "reference" / "README.md", target)
            if not resolved.exists():
                broken.append(f"reference/README.md: [{label}]({target})")
        assert not broken, "Broken links in reference/README.md:\n" + "\n".join(broken)

    def test_contributing_links(self):
        broken = []
        for label, target in self._extract_md_links(REPO_ROOT / "CONTRIBUTING.md"):
            resolved = self._resolve_link(REPO_ROOT / "CONTRIBUTING.md", target)
            if not resolved.exists():
                broken.append(f"CONTRIBUTING.md: [{label}]({target})")
        assert not broken, "Broken links in CONTRIBUTING.md:\n" + "\n".join(broken)


# ---------------------------------------------------------------------------
# Root-level required files
# ---------------------------------------------------------------------------


class TestRootFiles:
    """Open-source protocol repos require specific root-level files."""

    REQUIRED_FILES = [
        "README.md",
        "LICENSE",
        "PATENTS.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "CHANGELOG.md",
        "NOTICE",
    ]

    @pytest.mark.parametrize("filename", REQUIRED_FILES)
    def test_required_file_exists(self, filename: str):
        assert (REPO_ROOT / filename).exists(), f"{filename} missing from repo root"

    def test_license_is_apache(self):
        text = (REPO_ROOT / "LICENSE").read_text()
        assert "Apache License" in text

    def test_readme_protocol_first(self):
        """README must lead with the protocol, not pip install."""
        text = (REPO_ROOT / "README.md").read_text()
        protocol_pos = text.find("The Protocol")
        if protocol_pos == -1:
            protocol_pos = text.find("protocol")
        pip_pos = text.find("pip install")
        assert protocol_pos < pip_pos, (
            "README must introduce the protocol before pip install"
        )

    def test_readme_mentions_capsule_uri(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "capsule://" in text

    def test_readme_links_to_spec(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "./spec/" in text or "spec/" in text

    def test_readme_links_to_conformance(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "./conformance/" in text or "conformance/" in text

    def test_readme_lists_multiple_languages(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "Python" in text
        assert "TypeScript" in text


# ---------------------------------------------------------------------------
# CI configuration
# ---------------------------------------------------------------------------


class TestCIConfiguration:
    """CI must target the correct paths after restructure."""

    def test_python_ci_exists(self):
        assert (REPO_ROOT / ".github" / "workflows" / "python-ci.yaml").exists()

    def test_python_release_exists(self):
        assert (REPO_ROOT / ".github" / "workflows" / "python-release.yaml").exists()

    def test_python_ci_uses_correct_working_directory(self):
        text = (REPO_ROOT / ".github" / "workflows" / "python-ci.yaml").read_text()
        assert "reference/python" in text

    def test_python_ci_triggers_on_reference_paths(self):
        text = (REPO_ROOT / ".github" / "workflows" / "python-ci.yaml").read_text()
        assert "reference/python/**" in text

    def test_python_ci_triggers_on_conformance_changes(self):
        text = (REPO_ROOT / ".github" / "workflows" / "python-ci.yaml").read_text()
        assert "conformance/**" in text

    def test_python_ci_triggers_on_spec_changes(self):
        text = (REPO_ROOT / ".github" / "workflows" / "python-ci.yaml").read_text()
        assert "spec/**" in text

    def test_no_old_ci_yaml(self):
        """Old ci.yaml must not exist after rename."""
        assert not (REPO_ROOT / ".github" / "workflows" / "ci.yaml").exists()

    def test_no_old_release_yaml(self):
        assert not (REPO_ROOT / ".github" / "workflows" / "release.yaml").exists()

    def test_dependabot_targets_python_reference(self):
        text = (REPO_ROOT / ".github" / "dependabot.yml").read_text()
        assert "/reference/python" in text

    def test_dependabot_targets_typescript_reference(self):
        text = (REPO_ROOT / ".github" / "dependabot.yml").read_text()
        assert "/reference/typescript" in text

    def test_spec_change_template_exists(self):
        assert (REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "spec-change.md").exists()

    def test_no_old_cps_change_template(self):
        assert not (REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "cps_change.md").exists()

    def test_typescript_release_workflow_exists(self):
        assert (REPO_ROOT / ".github" / "workflows" / "typescript-release.yaml").exists()

    def test_typescript_release_triggers_on_tags(self):
        text = (REPO_ROOT / ".github" / "workflows" / "typescript-release.yaml").read_text()
        assert '"v*"' in text, "TypeScript release must trigger on version tags"

    def test_typescript_release_runs_conformance(self):
        text = (REPO_ROOT / ".github" / "workflows" / "typescript-release.yaml").read_text()
        assert "conformance" in text.lower(), (
            "TypeScript release must run conformance tests before publish"
        )

    def test_typescript_release_publishes_to_npm(self):
        text = (REPO_ROOT / ".github" / "workflows" / "typescript-release.yaml").read_text()
        assert "npm publish" in text, "TypeScript release must publish to npm"
