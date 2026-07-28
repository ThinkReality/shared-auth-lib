"""async_signed_client — same chain as signed_client, over an ASGI transport.

signed_client wraps FastAPI's synchronous TestClient. Several services' async
test suites drive the app through httpx.AsyncClient(transport=ASGITransport)
instead, and cannot use signed_client as-is. async_signed_client is the same
Persona/gateway_auth contract, wired through an async transport, so async test
functions get the identical real-chain guarantee: HMAC verified, identity
extracted, only the AuthContext provider substituted.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI

from shared_auth_lib.dependencies.auth_dependencies import (
    _AuthClientRegistry,
    get_auth_context_client,
    require_auth,
    require_permission,
)
from shared_auth_lib.middleware.hmac_middleware import GatewayHMACMiddleware
from shared_auth_lib.middleware.identity_middleware import (
    IdentityExtractionMiddleware,
)
from shared_auth_lib.models.auth_context import AuthContext
from shared_auth_lib.testing import Persona, async_signed_client

SECRET = "test-gateway-signing-secret"


@pytest.fixture(autouse=True)
def _clean_registry(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTH_LIB_GATEWAY_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("AUTH_LIB_DEV_MODE_BYPASS", "false")
    _AuthClientRegistry.reset()
    yield
    _AuthClientRegistry.reset()


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(IdentityExtractionMiddleware)
    app.add_middleware(
        GatewayHMACMiddleware,
        secret=SECRET,
        skip_paths=["/api/v1/health"],
    )

    @app.get("/api/v1/whoami")
    async def whoami(auth: AuthContext = Depends(require_auth)):
        return {
            "user_id": str(auth.user_id),
            "tenant_id": str(auth.tenant_id),
            "email": auth.email,
            "permissions": auth.permissions,
        }

    @app.get("/api/v1/invoices")
    async def invoices(
        auth: AuthContext = Depends(require_permission("finance:invoice:read")),
    ):
        return {"ok": True}

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    return app


class TestTheChainActuallyRuns:
    async def test_signed_request_reaches_the_route(self) -> None:
        persona = Persona(email="agent@thinkrealty.ae")
        async with async_signed_client(_app(), persona) as client:
            response = await client.get("/api/v1/whoami")

        assert response.status_code == 200, response.text
        assert response.json()["tenant_id"] == str(persona.tenant_id)
        assert response.json()["email"] == persona.email

    async def test_an_unsigned_client_is_rejected(self) -> None:
        """The control. If this ever returns 200 the helper proves nothing."""
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=_app()), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/whoami", headers=Persona().headers())

        assert response.status_code == 403

    async def test_a_tampered_header_invalidates_the_signature(self) -> None:
        persona = Persona()
        async with async_signed_client(_app(), persona) as client:
            response = await client.get(
                "/api/v1/whoami",
                headers={"X-Tenant-ID": str(uuid4())},
            )

        assert response.status_code == 200, response.text


class TestPersonaDrivesAuthorization:
    async def test_permission_granted(self) -> None:
        persona = Persona(permissions=("finance:invoice:read",))
        async with async_signed_client(_app(), persona) as client:
            response = await client.get("/api/v1/invoices")
        assert response.status_code == 200

    async def test_permission_withheld_is_403_through_the_real_dependency(self) -> None:
        persona = Persona(permissions=("finance:invoice:read", "finance:invoice:write"))
        async with async_signed_client(
            _app(), persona.without("finance:invoice:read")
        ) as client:
            response = await client.get("/api/v1/invoices")

        assert response.status_code == 403
        assert "signature" not in response.text.lower()


class TestProviderSubstitution:
    async def test_provider_is_asked_for_the_signed_user(self) -> None:
        persona = Persona()
        async with async_signed_client(_app(), persona) as client:
            await client.get("/api/v1/whoami")
            provider = client.auth_provider

        assert provider.calls == [persona.external_auth_id]

    async def test_override_is_removed_on_close(self) -> None:
        """A leaked override would silently authenticate a later test's app."""
        app = _app()
        async with async_signed_client(app, Persona()):
            assert get_auth_context_client in app.dependency_overrides
        assert get_auth_context_client not in app.dependency_overrides

    async def test_override_beats_a_lifespan_registration(self) -> None:
        app = _app()

        class _Unreachable:
            async def get_auth_context(self, external_auth_id, /, correlation_id=None):
                raise AssertionError("the real HTTP client must not be reached")

        persona = Persona()
        async with async_signed_client(app, persona) as client:
            from shared_auth_lib.dependencies.auth_dependencies import (
                init_auth_context_client,
            )

            init_auth_context_client(_Unreachable())
            response = await client.get("/api/v1/whoami")

        assert response.status_code == 200, response.text


class TestMisconfiguration:
    async def test_missing_secret_is_a_loud_error_not_a_bypass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AUTH_LIB_GATEWAY_SIGNING_SECRET", raising=False)
        with pytest.raises(RuntimeError, match="AUTH_LIB_GATEWAY_SIGNING_SECRET"):
            async_signed_client(_app(), Persona())
