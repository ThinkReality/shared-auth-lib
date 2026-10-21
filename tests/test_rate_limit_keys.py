from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI, Request
from httpx import ASGITransport, AsyncClient

from tr_shared.client_ip import client_ip

from shared_auth_lib import client_rate_limit_key, user_rate_limit_key
from shared_auth_lib.dependencies.auth_dependencies import _AuthClientRegistry
from shared_auth_lib.middleware.hmac_middleware import GatewayHMACMiddleware
from shared_auth_lib.middleware.identity_middleware import (
    IdentityExtractionMiddleware,
)
from shared_auth_lib.testing import Persona, async_signed_client

SECRET = "test-gateway-signing-secret"
CLIENT = "203.0.113.9"
EDGE_SEEN = "198.51.100.4"


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
        GatewayHMACMiddleware, secret=SECRET, skip_paths=["/api/v1/open/"]
    )

    @app.get("/api/v1/ip")
    async def signed_ip(request: Request) -> dict[str, str]:
        return {"ip": client_ip(request)}

    @app.get("/api/v1/open/ip")
    async def open_ip(request: Request) -> dict[str, str]:
        return {"ip": client_ip(request)}

    @app.get("/api/v1/user-key")
    async def user_key(key: str = Depends(user_rate_limit_key)) -> dict[str, str]:
        return {"key": key}

    @app.get("/api/v1/open/client-key")
    async def client_key(
        key: str = Depends(client_rate_limit_key),
    ) -> dict[str, str]:
        return {"key": key}

    return app


def _unsigned() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=_app()), base_url="http://test")


class TestClientIp:
    async def test_a_gateway_signed_request_is_the_ip_the_gateway_saw(self) -> None:
        async with async_signed_client(_app(), Persona()) as client:
            response = await client.get(
                "/api/v1/ip",
                headers={"X-Original-IP": CLIENT, "X-Real-IP": EDGE_SEEN},
            )

        assert response.json() == {"ip": CLIENT}

    async def test_an_unsigned_request_cannot_claim_a_gateway_ip(self) -> None:
        """X-Original-IP is not covered by the signature, so only a verified request may be believed."""
        async with _unsigned() as client:
            response = await client.get(
                "/api/v1/open/ip",
                headers={"X-Original-IP": CLIENT, "X-Real-IP": EDGE_SEEN},
            )

        assert response.json() == {"ip": EDGE_SEEN}

    async def test_without_an_edge_header_it_is_the_socket_peer(self) -> None:
        async with _unsigned() as client:
            response = await client.get("/api/v1/open/ip")

        assert response.json() == {"ip": "127.0.0.1"}


class TestRateLimitKeys:
    async def test_the_user_key_is_the_authenticated_user(self) -> None:
        persona = Persona()
        async with async_signed_client(_app(), persona) as client:
            response = await client.get("/api/v1/user-key")

        assert response.json() == {"key": f"user:{persona.user_id}"}

    async def test_the_user_key_refuses_an_unauthenticated_caller(self) -> None:
        async with _unsigned() as client:
            response = await client.get(
                "/api/v1/user-key", headers=Persona().headers()
            )

        assert response.status_code == 403

    async def test_the_client_key_is_the_client_ip(self) -> None:
        async with _unsigned() as client:
            response = await client.get(
                "/api/v1/open/client-key", headers={"X-Real-IP": EDGE_SEEN}
            )

        assert response.json() == {"key": f"ip:{EDGE_SEEN}"}
