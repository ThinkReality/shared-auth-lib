"""Tests for FastAPI authorization dependencies."""

from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from structlog.testing import capture_logs
from tr_shared.contracts import UNAVAILABLE_RETRY_AFTER_SECONDS
from tr_shared.middleware import register_exception_handlers
from tr_shared.schemas import build_error_envelope

from shared_auth_lib.dependencies.auth_dependencies import (
    AuthContextProvider,
    get_auth_context_client,
    optional_auth,
    require_any_role,
    require_auth,
    require_permission,
)
from shared_auth_lib.exceptions import AuthContextNotFoundError
from shared_auth_lib.middleware.identity_middleware import (
    IdentityExtractionMiddleware,
)
from shared_auth_lib.models.auth_context import AuthContext
from shared_auth_lib.services.auth_context_client import (
    AuthContextClient,
)
from tests.crm_core_stub import auth_context_client

USER_ID = uuid4()
TENANT_ID = uuid4()


MOCK_AUTH_CONTEXT = AuthContext(
    external_auth_id=USER_ID,
    user_id=uuid4(),
    email="test@thinkrealty.ae",
    tenant_id=TENANT_ID,
    roles=["admin", "sales_agent"],
    permissions=["user:read", "listing:create", "listing:read"],
    is_active=True,
    is_suspended=False,
)


def _mock_client(
    auth_context: AuthContext | None = None,
    raise_not_found: bool = False,
) -> AsyncMock:
    client = AsyncMock(spec=AuthContextClient)
    if raise_not_found:
        client.get_auth_context.side_effect = AuthContextNotFoundError("not found")
    else:
        client.get_auth_context.return_value = auth_context or MOCK_AUTH_CONTEXT
    return client


def _create_app(provider: AuthContextProvider) -> FastAPI:
    app = FastAPI()
    app.add_middleware(IdentityExtractionMiddleware)
    # Every service in the fleet installs these at startup. Without them this app
    # fell back to Starlette's default renderer, so these tests asserted a body
    # shape that no service actually returns — and would have kept passing while
    # the real canonical envelope regressed.
    register_exception_handlers(app)

    app.dependency_overrides[get_auth_context_client] = lambda: provider

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
        auth: AuthContext = Depends(require_permission("listing:create")),
    ):
        return {"user_id": str(auth.user_id)}

    @app.get("/require-missing-permission")
    async def route_require_missing_permission(
        auth: AuthContext = Depends(require_permission("user:delete")),
    ):
        return {"user_id": str(auth.user_id)}

    @app.get("/require-any-role")
    async def route_require_any_role(
        auth: AuthContext = Depends(require_any_role(["super_admin", "admin"])),
    ):
        return {"user_id": str(auth.user_id)}

    @app.get("/optional-auth")
    async def route_optional_auth(
        request: Request,
        auth: AuthContext | None = Depends(optional_auth),
    ):
        state_set = getattr(request.state, "auth_context", None) is not None
        if auth is None:
            return {"authenticated": False, "state_set": state_set}
        return {
            "authenticated": True,
            "user_id": str(auth.user_id),
            "state_set": state_set,
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
        assert resp.json()["error"]["code"] == "AUTHLIB_AUTH_001"
        # RFC 9110 §11.6.1: a 401 must name the scheme the client should use.
        assert resp.headers["www-authenticate"] == "Bearer"

    def test_user_not_found_returns_401(self):
        mock = _mock_client(raise_not_found=True)
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 401

    def test_inactive_user_returns_401(self):
        ctx = MOCK_AUTH_CONTEXT.model_copy(update={"is_active": False})
        mock = _mock_client(auth_context=ctx)
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "AUTHLIB_AUTH_003"
        assert "inactive" in resp.json()["error"]["detail"].lower()

    def test_suspended_user_returns_403(self):
        ctx = MOCK_AUTH_CONTEXT.model_copy(update={"is_suspended": True})
        mock = _mock_client(auth_context=ctx)
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/require-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "AUTHLIB_AUTH_004"
        assert "suspended" in resp.json()["error"]["detail"].lower()


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
        # The reason is machine-identifiable by code now; the permission name
        # stays in detail so an operator reading a log still sees which one.
        assert resp.json()["error"]["code"] == "AUTHLIB_AUTH_005"
        assert "user:delete" in resp.json()["error"]["detail"]


class TestRequireRoleIsGone:
    """v0.16.0 removed `require_role`: it resolved through the widening
    `AuthContext.has_role`, and had no callers anywhere in the fleet — every
    service already used `require_any_role`. Kept as a guard so it is not
    reintroduced without a deliberate decision."""

    def test_require_role_is_not_exported(self):
        import shared_auth_lib
        from shared_auth_lib.dependencies import auth_dependencies

        assert not hasattr(auth_dependencies, "require_role")
        assert not hasattr(shared_auth_lib, "require_role")
        assert "require_role" not in shared_auth_lib.__all__


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

    def test_inactive_user_returns_none(self):
        mock = _mock_client(
            MOCK_AUTH_CONTEXT.model_copy(update={"is_active": False})
        )
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/optional-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False

    def test_suspended_user_returns_none(self):
        mock = _mock_client(
            MOCK_AUTH_CONTEXT.model_copy(update={"is_suspended": True})
        )
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/optional-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False

    def test_authenticated_user_sets_request_state(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get(
            "/optional-auth",
            headers={"X-User-Id": str(USER_ID)},
        )
        assert resp.json()["state_set"] is True

    def test_unauthenticated_leaves_request_state_unset(self):
        mock = _mock_client()
        client = TestClient(_create_app(mock))
        resp = client.get("/optional-auth")
        assert resp.json()["state_set"] is False


SIGNED_IN = {"X-User-Id": str(USER_ID)}
BOTH_DEPENDENCIES = ["/require-auth", "/optional-auth"]


def _crm_core_answers(status: int):
    return lambda request: httpx.Response(status, json={})


def _crm_core_refuses(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("refused", request=request)


class TestAuthServiceUnavailable:
    @pytest.mark.parametrize("path", BOTH_DEPENDENCIES)
    @pytest.mark.parametrize(
        "handler",
        [
            pytest.param(_crm_core_answers(500), id="5xx"),
            pytest.param(_crm_core_refuses, id="connect-error"),
        ],
    )
    def test_unreachable_crm_core_is_503(self, handler, path):
        app = _create_app(auth_context_client(httpx.MockTransport(handler)))
        with TestClient(app) as client:
            resp = client.get(path, headers=SIGNED_IN)
        assert resp.status_code == 503
        assert resp.json()["error"]["code"] == "AUTHLIB_SERVICE_UNAVAILABLE_001"
        assert resp.headers["retry-after"] == str(UNAVAILABLE_RETRY_AFTER_SECONDS)

    @pytest.mark.parametrize("path", BOTH_DEPENDENCIES)
    def test_open_circuit_is_503_and_skips_crm_core(self, path):
        calls = []

        def failing(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(500, json={})

        crm_core = auth_context_client(
            httpx.MockTransport(failing),
            circuit_failure_threshold=1,
            circuit_recovery_timeout=9999,
        )
        with TestClient(_create_app(crm_core)) as client:
            first = client.get(path, headers=SIGNED_IN)
            second = client.get(path, headers=SIGNED_IN)
        assert (first.status_code, second.status_code) == (503, 503)
        assert len(calls) == 1

    def test_unavailable_is_logged_but_not_audited_as_auth_failure(self):
        crm_core = auth_context_client(httpx.MockTransport(_crm_core_refuses))
        app = _create_app(crm_core)
        with capture_logs() as logs, TestClient(app) as client:
            client.get("/require-auth", headers=SIGNED_IN)
        events = [entry["event"] for entry in logs]
        assert "auth_context_unavailable" in events
        assert "auth_failure" not in events

    def test_enveloped_404_is_still_401(self):
        not_found = build_error_envelope("AuthContext not found")
        crm_core = auth_context_client(
            httpx.MockTransport(lambda request: httpx.Response(404, json=not_found))
        )
        with TestClient(_create_app(crm_core)) as client:
            resp = client.get("/require-auth", headers=SIGNED_IN)
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "AUTHLIB_AUTH_002"
