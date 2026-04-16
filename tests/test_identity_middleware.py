"""Tests for IdentityExtractionMiddleware."""

from uuid import uuid4

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from shared_auth_lib.middleware.identity_middleware import (
    IdentityExtractionMiddleware,
    get_gateway_identity,
)
from shared_auth_lib.models.auth_context import (
    GatewayIdentityHeaders,
)


def _create_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(IdentityExtractionMiddleware)

    @app.get("/check-identity")
    async def check_identity(
        identity: GatewayIdentityHeaders = Depends(
            get_gateway_identity
        ),
    ):
        return {
            "user_id": (
                str(identity.user_id)
                if identity.user_id
                else None
            ),
            "user_role": identity.user_role,
            "tenant_id": (
                str(identity.tenant_id)
                if identity.tenant_id
                else None
            ),
            "user_email": identity.user_email,
            "auth_provider": identity.auth_provider,
            "correlation_id": identity.correlation_id,
        }

    return app


class TestIdentityExtractionMiddleware:
    def test_valid_headers_extracted(self):
        client = TestClient(_create_app())
        uid = str(uuid4())
        tid = str(uuid4())
        resp = client.get(
            "/check-identity",
            headers={
                "X-User-Id": uid,
                "X-User-Role": "ADMIN",
                "X-Tenant-ID": tid,
                "X-User-Email": "test@example.com",
                "X-Auth-Provider": "supabase",
                "X-Correlation-Id": "corr-123",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_id"] == uid
        assert data["user_role"] == "ADMIN"
        assert data["tenant_id"] == tid
        # X-User-Email is intentionally NOT extracted (unsigned header)
        assert data["user_email"] is None
        assert data["auth_provider"] == "supabase"
        assert data["correlation_id"] == "corr-123"

    def test_missing_headers_returns_none_fields(self):
        client = TestClient(_create_app())
        resp = client.get("/check-identity")
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_id"] is None
        assert data["user_role"] is None
        assert data["tenant_id"] is None
        assert data["user_email"] is None

    def test_invalid_uuid_falls_back_to_empty_identity(self):
        client = TestClient(_create_app())
        resp = client.get(
            "/check-identity",
            headers={"X-User-Id": "not-a-uuid"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_id"] is None

    def test_invalid_tenant_uuid_falls_back_to_empty_identity(self):
        client = TestClient(_create_app())
        resp = client.get(
            "/check-identity",
            headers={"X-Tenant-ID": "not-a-uuid"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] is None

    def test_default_auth_provider_when_header_present(self):
        client = TestClient(_create_app())
        resp = client.get(
            "/check-identity",
            headers={
                "X-Auth-Provider": "clerk",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["auth_provider"] == "clerk"

    def test_auth_provider_defaults_to_supabase(self):
        client = TestClient(_create_app())
        uid = str(uuid4())
        resp = client.get(
            "/check-identity",
            headers={"X-User-Id": uid},
        )
        assert resp.status_code == 200
        assert resp.json()["auth_provider"] == "supabase"


class _MockCorrelationIDMiddleware(BaseHTTPMiddleware):
    """Simulates CorrelationIDMiddleware setting request.state."""

    def __init__(self, app, correlation_id: str):
        super().__init__(app)
        self._correlation_id = correlation_id

    async def dispatch(self, request: Request, call_next):
        request.state.correlation_id = self._correlation_id
        return await call_next(request)


def _create_app_with_correlation_middleware(
    correlation_id: str,
) -> FastAPI:
    app = FastAPI()
    # IdentityExtraction added first (runs second, inner)
    app.add_middleware(IdentityExtractionMiddleware)
    # Correlation middleware added second (runs first, outer)
    app.add_middleware(
        _MockCorrelationIDMiddleware,
        correlation_id=correlation_id,
    )

    @app.get("/check-identity")
    async def check_identity(
        identity: GatewayIdentityHeaders = Depends(
            get_gateway_identity
        ),
    ):
        return {
            "correlation_id": identity.correlation_id,
        }

    return app


class TestCorrelationIDFallback:
    def test_correlation_id_falls_back_to_request_state(self):
        """When no X-Correlation-Id header, use request.state."""
        app = _create_app_with_correlation_middleware(
            "state-corr-456"
        )
        client = TestClient(app)
        resp = client.get("/check-identity")
        assert resp.status_code == 200
        assert resp.json()["correlation_id"] == "state-corr-456"

    def test_correlation_id_header_takes_precedence(self):
        """X-Correlation-Id header wins over request.state."""
        app = _create_app_with_correlation_middleware(
            "state-corr-789"
        )
        client = TestClient(app)
        resp = client.get(
            "/check-identity",
            headers={"X-Correlation-Id": "header-corr-123"},
        )
        assert resp.status_code == 200
        assert (
            resp.json()["correlation_id"] == "header-corr-123"
        )
