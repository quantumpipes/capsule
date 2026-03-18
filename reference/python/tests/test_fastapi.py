# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the FastAPI integration (mount_capsules).

These tests require fastapi and httpx. They are skipped automatically
if either dependency is not installed.
"""

from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from qp_capsule import CapsuleType, TriggerSection  # noqa: E402
from qp_capsule.audit import Capsules  # noqa: E402
from qp_capsule.capsule import Capsule  # noqa: E402
from qp_capsule.integrations.fastapi import mount_capsules  # noqa: E402


@pytest.fixture
async def app_and_capsules(tmp_path: Path):
    """Create a FastAPI app with capsule routes mounted."""
    db = tmp_path / "test.db"
    capsules = Capsules(str(db))

    app = FastAPI()
    mount_capsules(app, capsules, prefix="/capsules")

    yield app, capsules
    await capsules.close()


@pytest.fixture
def client(app_and_capsules):
    """Sync test client for FastAPI."""
    app, _ = app_and_capsules
    return TestClient(app)


async def _seed_capsules(capsules: Capsules, count: int = 3) -> list[Capsule]:
    """Seal some capsules into storage for testing."""
    sealed = []
    for i in range(count):
        cap = Capsule(
            type=CapsuleType.AGENT if i % 2 == 0 else CapsuleType.TOOL,
            trigger=TriggerSection(source="test", request=f"task-{i}"),
        )
        result = await capsules.chain.seal_and_store(cap, seal=capsules.seal)
        sealed.append(result)
    return sealed


class TestFastAPIImportError:
    def test_mount_capsules_without_fastapi(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """mount_capsules raises CapsuleError when FastAPI is not installed."""
        import builtins

        from qp_capsule import CapsuleError

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "fastapi":
                raise ImportError("No module named 'fastapi'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        capsules_inst = Capsules(str(tmp_path / "test.db"))
        with pytest.raises(CapsuleError, match="FastAPI integration requires"):
            mount_capsules(object(), capsules_inst)


class TestMountCapsules:
    def test_mount_adds_routes(self, app_and_capsules) -> None:
        app, _ = app_and_capsules
        routes = [r.path for r in app.routes]
        assert "/capsules/" in routes
        assert "/capsules/verify" in routes
        assert "/capsules/{capsule_id}" in routes


class TestListCapsules:
    def test_list_capsules_empty(self, client: TestClient) -> None:
        resp = client.get("/capsules/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["capsules"] == []
        assert data["total"] == 0

    async def test_list_capsules_with_data(self, app_and_capsules) -> None:
        app, capsules = app_and_capsules
        await _seed_capsules(capsules, count=3)

        with TestClient(app) as tc:
            resp = tc.get("/capsules/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["capsules"]) == 3

    async def test_list_capsules_filtered(self, app_and_capsules) -> None:
        app, capsules = app_and_capsules
        await _seed_capsules(capsules, count=4)

        with TestClient(app) as tc:
            resp = tc.get("/capsules/?type=agent")
        assert resp.status_code == 200
        data = resp.json()
        for cap in data["capsules"]:
            assert cap["type"] == "agent"


class TestGetCapsule:
    async def test_get_capsule(self, app_and_capsules) -> None:
        app, capsules = app_and_capsules
        sealed = await _seed_capsules(capsules, count=1)
        capsule_id = str(sealed[0].id)

        with TestClient(app) as tc:
            resp = tc.get(f"/capsules/{capsule_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == capsule_id

    def test_get_capsule_404(self, client: TestClient) -> None:
        resp = client.get("/capsules/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404


SEAL_ENVELOPE_KEYS = {"hash", "signature", "signature_pq", "signed_at", "signed_by"}


class TestEndpointsIncludeSealFields:
    """Verify API responses include the cryptographic seal envelope."""

    async def test_list_capsules_includes_seal_fields(self, app_and_capsules) -> None:
        app, capsules = app_and_capsules
        await _seed_capsules(capsules, count=2)

        with TestClient(app) as tc:
            resp = tc.get("/capsules/")
        assert resp.status_code == 200
        data = resp.json()

        for cap in data["capsules"]:
            for key in SEAL_ENVELOPE_KEYS:
                assert key in cap, f"missing '{key}' in list response"
            assert len(cap["hash"]) == 64
            assert len(cap["signature"]) > 0
            assert cap["signed_at"] is not None
            assert cap["signed_by"] != ""

    async def test_get_capsule_includes_seal_fields(self, app_and_capsules) -> None:
        app, capsules = app_and_capsules
        sealed = await _seed_capsules(capsules, count=1)
        capsule_id = str(sealed[0].id)

        with TestClient(app) as tc:
            resp = tc.get(f"/capsules/{capsule_id}")
        assert resp.status_code == 200
        cap = resp.json()

        for key in SEAL_ENVELOPE_KEYS:
            assert key in cap, f"missing '{key}' in get response"
        assert cap["hash"] == sealed[0].hash
        assert cap["signature"] == sealed[0].signature
        assert cap["signed_by"] == sealed[0].signed_by


class TestVerifyChain:
    def test_verify_chain_empty(self, client: TestClient) -> None:
        resp = client.get("/capsules/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["capsules_verified"] == 0

    async def test_verify_chain_with_data(self, app_and_capsules) -> None:
        app, capsules = app_and_capsules
        await _seed_capsules(capsules, count=5)

        with TestClient(app) as tc:
            resp = tc.get("/capsules/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["capsules_verified"] == 5


class TestTenantFiltering:
    async def test_tenant_param_accepted(self, app_and_capsules) -> None:
        """tenant_id query param is accepted and passed through to storage."""
        app, capsules = app_and_capsules
        await _seed_capsules(capsules, count=2)

        with TestClient(app) as tc:
            resp = tc.get("/capsules/?tenant_id=some-tenant")
        assert resp.status_code == 200
        data = resp.json()
        assert "capsules" in data
        assert "total" in data

    async def test_verify_with_tenant_param(self, app_and_capsules) -> None:
        """Verify endpoint accepts tenant_id parameter."""
        app, capsules = app_and_capsules

        with TestClient(app) as tc:
            resp = tc.get("/capsules/verify?tenant_id=some-tenant")
        assert resp.status_code == 200
        assert resp.json()["valid"] is True
