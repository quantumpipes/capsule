"""
Repo hygiene tests for open-source launch readiness.

Guards against regressions when adding new examples, fixtures, or docs.
"""

import json
import re
from pathlib import Path

import pytest

PYTHON_ROOT = Path(__file__).parent.parent
REPO_ROOT = PYTHON_ROOT.parent.parent
CONFORMANCE_DIR = REPO_ROOT / "conformance"
SRC_DIR = PYTHON_ROOT / "src" / "qp_capsule"
EXAMPLES_DIR = REPO_ROOT / "examples"
DOCS_DIR = REPO_ROOT / "docs"


class TestExampleDomains:
    """New examples must use RFC 2606 placeholder domains, not internal ones."""

    def _scan_examples(self, pattern: str) -> list[str]:
        violations = []
        for path in EXAMPLES_DIR.glob("*.json"):
            matches = re.findall(pattern, path.read_text())
            if matches:
                violations.append(f"{path.name}: {matches}")
        return violations

    def test_no_non_example_dot_com_emails(self):
        """Example emails must use @example.com (RFC 2606)."""
        violations = self._scan_examples(r"[\w.-]+@(?!example\.com)[\w.-]+\.com")
        assert not violations, "Non-example.com emails in examples:\n" + "\n".join(violations)

    def test_no_dot_internal_hostnames(self):
        """Example hostnames must not use .internal."""
        violations = self._scan_examples(r"[\w.-]+\.internal\b")
        assert not violations, ".internal hostnames in examples:\n" + "\n".join(violations)


class TestPackageIntegrity:
    """Package markers and metadata must be correct."""

    def test_py_typed_marker_exists(self):
        """PEP 561 py.typed marker is required for typed package support."""
        assert (SRC_DIR / "py.typed").exists()

    def test_package_name_is_qp_capsule(self):
        """Package name must be qp-capsule."""
        import tomllib

        with open(PYTHON_ROOT / "pyproject.toml", "rb") as f:
            config = tomllib.load(f)
        assert config["project"]["name"] == "qp-capsule"

    def test_version_matches_changelog(self):
        """pyproject.toml version must match the latest CHANGELOG entry."""
        import tomllib

        with open(PYTHON_ROOT / "pyproject.toml", "rb") as f:
            version = tomllib.load(f)["project"]["version"]
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text()
        match = re.search(r"\[(\d+\.\d+\.\d+)\]", changelog)
        assert match and match.group(1) == version


class TestGoldenFixtures:
    """Golden fixture file must be structurally valid."""

    @pytest.fixture()
    def fixtures(self) -> dict:
        with open(CONFORMANCE_DIR / "fixtures.json") as f:
            return json.load(f)

    def test_fixture_count_is_fifteen(self, fixtures: dict):
        """CPS v1.0 defines exactly 16 golden test vectors."""
        assert len(fixtures["fixtures"]) == 16

    def test_fixture_names_are_unique(self, fixtures: dict):
        names = [f["name"] for f in fixtures["fixtures"]]
        assert len(names) == len(set(names))

    def test_fixture_hashes_are_valid_sha3_hex(self, fixtures: dict):
        for f in fixtures["fixtures"]:
            assert re.fullmatch(r"[0-9a-f]{64}", f["sha3_256_hash"]), f["name"]


class TestVersionAlignment:
    """All version markers must agree across the repo."""

    def test_spec_version_file_matches_changelog(self):
        """spec/VERSION must match the major.minor of the latest CHANGELOG release."""
        spec_version = (REPO_ROOT / "spec" / "VERSION").read_text().strip()
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text()
        match = re.search(r"\[(\d+)\.(\d+)\.\d+\]", changelog)
        assert match, "No versioned release found in CHANGELOG"
        expected = f"{match.group(1)}.{match.group(2)}"
        assert spec_version == expected, (
            f"spec/VERSION ({spec_version}) != CHANGELOG ({expected})"
        )

    def test_python_init_version_matches_pyproject(self):
        """__version__ in __init__.py must match pyproject.toml."""
        import tomllib

        with open(PYTHON_ROOT / "pyproject.toml", "rb") as f:
            pyproject_version = tomllib.load(f)["project"]["version"]
        init_text = (SRC_DIR / "__init__.py").read_text()
        match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
        assert match, "__version__ not found in __init__.py"
        assert match.group(1) == pyproject_version, (
            f"__init__.py ({match.group(1)}) != pyproject.toml ({pyproject_version})"
        )

    def test_changelog_has_versioned_release(self):
        """CHANGELOG must have at least one versioned release (not just [Unreleased])."""
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text()
        releases = re.findall(r"## \[(\d+\.\d+\.\d+)\]", changelog)
        assert len(releases) >= 1, "No versioned releases in CHANGELOG"

    def test_changelog_unreleased_section_is_empty_or_minimal(self):
        """[Unreleased] section should not contain leftover content after a release."""
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text()
        unreleased_match = re.search(
            r"## \[Unreleased\]\s*\n(.*?)(?=\n## \[|$)", changelog, re.DOTALL,
        )
        if unreleased_match:
            content = unreleased_match.group(1).strip()
            content = content.lstrip("-").strip()
            assert len(content) < 50, (
                f"[Unreleased] section has substantial leftover content: {content[:100]}"
            )


class TestCIMakefileAlignment:
    """CI workflow must match Makefile so local and remote checks agree."""

    def test_ruff_check_scope_matches(self):
        ci = (REPO_ROOT / ".github" / "workflows" / "python-ci.yaml").read_text()
        makefile = (PYTHON_ROOT / "Makefile").read_text()
        ci_paths = set(re.search(r"ruff check (.+)", ci).group(1).split())  # type: ignore[union-attr]
        make_paths = set(re.search(r"ruff check (.+)", makefile).group(1).split())  # type: ignore[union-attr]
        assert ci_paths == make_paths
