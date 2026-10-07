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

    @app.get("/")
    async def root():
        return {"status": "root"}

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
        assert body["error"]["code"] == "AUTHLIB_AUTH_008"

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
        assert body["error"]["code"] == "AUTHLIB_AUTH_008"

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
        assert body["error"]["code"] == "AUTHLIB_AUTH_009"

    def test_non_ascii_signature_returns_403_not_500(self):
        headers = _sign_headers()
        headers_bytes = {**headers, "X-Gateway-Signature": "é".encode() * 32}
        resp = TestClient(_create_app()).get("/protected", headers=headers_bytes)
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "AUTHLIB_AUTH_009"

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

    def test_root_skip_path_matches_root_only(self):
        """`"/"` skips the root route and nothing else.

        A trailing slash means prefix-match, but `"/"` prefixes every path, so
        treating it as one silently disables HMAC verification service-wide.
        """
        client = TestClient(_create_app(skip_paths=["/"]))

        assert client.get("/").status_code == 200
        assert client.get("/protected").status_code == 403
        assert client.get("/internal/status").status_code == 403
        assert client.get("/health").status_code == 403


class TestSkipPathMatching:
    """Exact semantics of the skip_paths mini-language.

    Trailing slash = prefix match; no trailing slash = exact match; `"/"` is
    root-only. Table-driven so a regression names the exact pair that broke.
    """

    CASES = [
        # (skip_paths, path, should_skip)
        (["/"], "/", True),
        (["/"], "/api/v1/leads", False),
        (["/"], "/health", False),
        (["/api/v1/internal/"], "/api/v1/internal/", True),
        (["/api/v1/internal/"], "/api/v1/internal", True),
        (["/api/v1/internal/"], "/api/v1/internal/auth-context/1", True),
        (["/api/v1/internal/"], "/api/v1/internalize", False),
        (["/api/v1/health"], "/api/v1/health", True),
        (["/api/v1/health"], "/api/v1/health/ready", False),
        (["/api/v1/health"], "/api/v1/healthz", False),
    ]

    def test_skip_path_matching(self):
        for skip_paths, path, expected in self.CASES:
            mw = GatewayHMACMiddleware(
                app=None, secret=SECRET, skip_paths=skip_paths
            )
            assert mw._should_skip(path) is expected, (
                f"skip_paths={skip_paths!r} path={path!r} "
                f"expected skip={expected}, got {not expected}"
            )


REFUSED_REDIS_URL = "redis://127.0.0.1:1/0"


def replay_guarded(
    redis_url: str, *, replay_protection_fail_open: bool = True
) -> GatewayHMACMiddleware:
    app = FastAPI()

    @app.get("/protected")
    async def protected():
        return {"status": "ok"}

    return GatewayHMACMiddleware(
        app,
        secret=SECRET,
        redis_url=redis_url,
        replay_protection_fail_open=replay_protection_fail_open,
    )


class TestGatewayHMACReplayProtection:
    def test_no_redis_url_disables_dedup(self):
        client = TestClient(_create_app())
        headers = _sign_headers()
        assert client.get("/protected", headers=headers).status_code == 200
        assert client.get("/protected", headers=headers).status_code == 200

    def test_unreachable_redis_fails_open_and_counts_a_skip_not_a_success(self):
        guard = replay_guarded(REFUSED_REDIS_URL)

        resp = TestClient(guard).get("/protected", headers=_sign_headers())

        assert resp.status_code == 200
        assert guard.hmac_stats == {
            "success": 0,
            "failure_missing_headers": 0,
            "failure_invalid_signature": 0,
            "failure_replay": 0,
            "replay_check_skipped": 1,
            "total": 1,
            "failure_rate": 0.0,
        }

    def test_unreachable_redis_fails_closed_when_configured(self):
        guard = replay_guarded(REFUSED_REDIS_URL, replay_protection_fail_open=False)

        resp = TestClient(guard).get("/protected", headers=_sign_headers())

        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "AUTHLIB_AUTH_010"
        assert guard.hmac_stats["replay_check_skipped"] == 1
        assert guard.hmac_stats["failure_replay"] == 0

    def test_a_redis_url_that_drops_the_proxy_guards_fails_at_construction(self):
        with pytest.raises(ValueError, match="redis://"):
            replay_guarded("rediss://127.0.0.1:6379/0")

    def test_forged_tenant_id_returns_403(self):
        client = TestClient(_create_app())
        headers = _sign_headers()
        # Forge the tenant ID after signing
        headers["X-Tenant-ID"] = "00000000-0000-0000-0000-000000000000"
        resp = client.get("/protected", headers=headers)
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "AUTHLIB_AUTH_009"

    def test_no_headers_on_non_skip_path_returns_403(self):
        client = TestClient(_create_app())
        resp = client.get("/protected")
        assert resp.status_code == 403

    def test_internal_route_is_skipped(self):
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
