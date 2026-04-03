"""Tests for FastAPI authorization dependencies."""

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from shared_auth_lib.dependencies.auth_dependencies import (
    _AuthClientRegistry,
    get_auth_context_client,
    init_auth_context_client,
    optional_auth,
    require_any_role,
    require_auth,
    require_permission,
    require_role,
)
from shared_auth_lib.exceptions import AuthContextNotFoundError
from shared_auth_lib.middleware.identity_middleware import (
    IdentityExtractionMiddleware,
)
from shared_auth_lib.models.auth_context import AuthContext
from shared_auth_lib.services.auth_context_client import (
    AuthContextClient,
)

USER_ID = uuid4()
TENANT_ID = uuid4()


@pytest.fixture(autouse=True)
def reset_auth_registry():
    """Ensure registry is clean before and after every test."""
    _AuthClientRegistry.reset()
    yield
    _AuthClientRegistry.reset()

MOCK_AUTH_CONTEXT = AuthContext(
    external_auth_id=USER_ID,
    user_id=uuid4(),
    email="test@thinkrealty.ae",
    tenant_id=TENANT_ID,
    roles=["ADMIN", "AGENT"],
    permissions=["user:read", "listing:create", "listing:read"],
    is_active=True,
    is_suspended=False,
    role_hierarchy=["ADMIN", "MANAGER", "AGENT"],
)


def _mock_client(
    auth_context: AuthContext | None = None,
    raise_not_found: bool = False,
) -> AsyncMock:
    client = AsyncMock(spec=AuthContextClient)
    if raise_not_found:
        client.get_auth_context.side_effect = (
            AuthContextNotFoundError("not found")
        )
    else:
        client.get_auth_context.return_value = (
            auth_context or MOCK_AUTH_CONTEXT
        )
    return client


def _create_app(mock_client: AsyncMock) -> FastAPI:
    app = FastAPI()
    app.add_middleware(IdentityExtractionMiddleware)

    init_auth_context_client(mock_client)

    @app.get("/require-auth")
    async def route_require_auth(
        auth: AuthContext = Depends(require_auth),
    ):
        return {
            "user_id": str(auth.user_id),
            "email": auth.email,
        }

    @app.get("/require-permission")
    async def route_require_permission(
        auth: AuthContext = Depends(
            require_permission("listing:create")
        ),
    ):
        return {"user_id": str(auth.user_id)}

    @app.get("/require-missing-permission")
    async def route_require_missing_permission(
        auth: AuthContext = Depends(
            require_permission("user:delete")
        ),
    ):
        return {"user_id": str(auth.user_id)}

    @app.get("/require-role")
    async def route_require_role(
        auth: AuthContext = Depends(require_role("ADMIN")),
    ):
        return {"user_id": str(auth.user_id)}

    @app.get("/require-missing-role")
    async def route_require_missing_role(
        auth: AuthContext = Depends(
            require_role("SUPER_ADMIN")
        ),
    ):
        return {"user_id": str(auth.user_id)}

    @app.get("/require-any-role")
    async def route_require_any_role(
        auth: AuthContext = Depends(
            require_any_role(["MANAGER", "ADMIN"])
        ),
    ):
        return {"user_id": str(auth.user_id)}

    @app.get("/optional-auth")
    async def route_optional_auth(
        auth: AuthContext | None = Depends(optional_auth),
    ):
        if auth is None:
            return {"authenticated": False}
        return {
            "authenticated": True,
            "user_id": str(auth.user_id),
        }

    return app


class TestRequireAuth:
    def test_authenticated_user_passes(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "test@thinkrealty.ae"

    def test_missing_user_id_returns_401(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get("/require-auth")
        assert resp.status_code == 401

    def test_user_not_found_returns_401(self):
        mock = _mock_client(raise_not_found=True)
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 401

    def test_inactive_user_returns_401(self):
        ctx = MOCK_AUTH_CONTEXT.model_copy(
            update={"is_active": False}
        )
        mock = _mock_client(auth_context=ctx)
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 401
        assert "inactive" in resp.json()["detail"].lower()

    def test_suspended_user_returns_403(self):
        ctx = MOCK_AUTH_CONTEXT.model_copy(
            update={"is_suspended": True}
        )
        mock = _mock_client(auth_context=ctx)
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 403
        assert "suspended" in resp.json()["detail"].lower()


class TestRequirePermission:
    def test_has_permission_passes(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-permission",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 200

    def test_missing_permission_returns_403(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-missing-permission",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 403
        assert "user:delete" in resp.json()["detail"]


class TestRequireRole:
    def test_has_role_passes(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-role",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 200

    def test_missing_role_returns_403(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-missing-role",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 403
        assert "SUPER_ADMIN" in resp.json()["detail"]


class TestRequireAnyRole:
    def test_has_any_matching_role_passes(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-any-role",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 200


class TestOptionalAuth:
    def test_authenticated_user_returns_context(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/optional-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True

    def test_unauthenticated_returns_none(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get("/optional-auth")
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False

    def test_user_not_found_returns_none(self):
        mock = _mock_client(raise_not_found=True)
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/optional-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False
