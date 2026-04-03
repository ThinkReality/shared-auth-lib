"""Tests for GatewayHMACMiddleware."""

from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shared_auth_lib.middleware.hmac_middleware import (
    GatewayHMACMiddleware,
)
from shared_auth_lib.services.hmac_verifier import compute_signature

SECRET = "test-secret-key-32-bytes-long!!!"


def _create_app(
    skip_paths: list[str] | None = None,
    tolerance: int = 30,
) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        GatewayHMACMiddleware,
        secret=SECRET,
        skip_paths=skip_paths,
        tolerance_seconds=tolerance,
    )

    @app.get("/protected")
    async def protected():
        return {"status": "ok"}

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    @app.get("/docs")
    async def docs():
        return {"status": "docs"}

    @app.get("/internal/status")
    async def internal_status():
        return {"status": "internal"}

    return app


def _sign_headers(
    method: str = "GET",
    path: str = "/protected",
    extra_headers: dict | None = None,
) -> dict[str, str]:
    ts = datetime.now(UTC).isoformat()
    headers = {
        "X-User-ID": "550e8400-e29b-41d4-a716-446655440000",
        "X-User-Role": "ADMIN",
        "X-Tenant-ID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "X-Correlation-ID": "corr-test",
        "X-Gateway-Timestamp": ts,
    }
    if extra_headers:
        headers.update(extra_headers)

    sig = compute_signature(
        method=method,
        path=path,
        headers=headers,
        secret=SECRET,
        timestamp=ts,
    )
    headers["X-Gateway-Signature"] = sig
    return headers


class TestGatewayHMACMiddleware:
    def test_valid_signature_passes(self):
        client = TestClient(_create_app())
        headers = _sign_headers()
        resp = client.get("/protected", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_missing_signature_returns_403(self):
        client = TestClient(_create_app())
        ts = datetime.now(UTC).isoformat()
        resp = client.get(
            "/protected",
            headers={"X-Gateway-Timestamp": ts},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "HMAC_MISSING_HEADERS"

    def test_missing_timestamp_returns_403(self):
        client = TestClient(_create_app())
        resp = client.get(
            "/protected",
            headers={
                "X-Gateway-Signature": "abc123",
            },
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "HMAC_MISSING_HEADERS"

    def test_invalid_signature_returns_403(self):
        client = TestClient(_create_app())
        ts = datetime.now(UTC).isoformat()
        resp = client.get(
            "/protected",
            headers={
                "X-Gateway-Signature": "0" * 64,
                "X-Gateway-Timestamp": ts,
            },
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "HMAC_INVALID_SIGNATURE"

    def test_health_skipped_by_default(self):
        client = TestClient(_create_app())
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_docs_skipped_by_default(self):
        client = TestClient(_create_app())
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_internal_skipped_by_default(self):
        client = TestClient(_create_app())
        resp = client.get("/internal/status")
        assert resp.status_code == 200

    def test_custom_skip_paths(self):
        app = _create_app(skip_paths=["/protected"])
        client = TestClient(app)
        resp = client.get("/protected")
        assert resp.status_code == 200

    def test_forged_tenant_id_returns_403(self):
        """Request signed with one tenant but forwarded with a different tenant is rejected."""
        client = TestClient(_create_app())
        headers = _sign_headers()
        # Forge the tenant ID after signing
        headers["X-Tenant-ID"] = "00000000-0000-0000-0000-000000000000"
        resp = client.get("/protected", headers=headers)
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "HMAC_INVALID_SIGNATURE"

    def test_no_headers_on_non_skip_path_returns_403(self):
        client = TestClient(_create_app())
        resp = client.get("/protected")
        assert resp.status_code == 403

    def test_internal_route_is_skipped(self):
        """/internal/anything is skipped — service-to-service path."""
        app = _create_app()

        @app.get("/internal/auth-context/abc")
        async def s2s():
            return {"ok": True}

        resp = TestClient(app).get("/internal/auth-context/abc")
        assert resp.status_code == 200

    def test_internal_prefix_variant_requires_hmac(self):
        """/internalize must NOT be skipped — only /internal/ prefix is exempt."""
        app = _create_app()

        @app.get("/internalize")
        async def internalize():
            return {"ok": True}

        resp = TestClient(app).get("/internalize")
        assert resp.status_code == 403
