from __future__ import annotations

import asyncio
import os

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from structlog.testing import capture_logs

from shared_auth_lib.dependencies.auth_dependencies import _AuthClientRegistry
from shared_auth_lib.middleware import install_standard_middleware
from shared_auth_lib.testing import Persona, async_signed_client
from tr_shared.middleware import register_exception_handlers

SECRET = "test-gateway-signing-secret"
REFUSING_REDIS = "redis://127.0.0.1:1/0"
BROWSER = "198.51.100.7"
EDGE = "100.64.0.2"


@pytest.fixture
def replay_store() -> str:
    url = os.getenv("TEST_REDIS_URL")
    if not url:
        pytest.skip("TEST_REDIS_URL not set — a signed request needs a replay store")
    return url


@pytest.fixture(autouse=True)
def _signing_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTH_LIB_GATEWAY_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("AUTH_LIB_DEV_MODE_BYPASS", "false")
    _AuthClientRegistry.reset()
    yield
    _AuthClientRegistry.reset()


def _app(redis_url: str = REFUSING_REDIS) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app, code_prefix="TEST")

    @app.get("/api/v1/things")
    async def things() -> dict:
        return {}

    @app.get("/api/v1/open")
    async def open_route() -> dict:
        return {}

    install_standard_middleware(
        app,
        service_name="test-service",
        environment="test",
        cors=None,
        hmac_secret=SECRET,
        hmac_skip_paths=["/api/v1/open"],
        hmac_redis_url=redis_url,
    )
    return app


def _completed(logs: list[dict]) -> dict:
    return next(entry for entry in logs if entry["event"] == "request_completed")


async def test_a_signed_request_is_logged_with_the_ip_the_gateway_forwarded(
    replay_store: str,
) -> None:
    with capture_logs() as logs:
        async with (
            asyncio.timeout(10),
            async_signed_client(_app(replay_store), Persona()) as client,
        ):
            response = await client.get(
                "/api/v1/things",
                headers={"X-Original-IP": BROWSER, "X-Real-IP": EDGE},
            )

    assert response.status_code == 200, response.text
    assert _completed(logs)["client_ip"] == BROWSER


async def test_an_unsigned_request_is_logged_with_the_edge_ip() -> None:
    transport = ASGITransport(app=_app())
    with capture_logs() as logs:
        async with (
            asyncio.timeout(10),
            AsyncClient(transport=transport, base_url="http://test") as client,
        ):
            response = await client.get(
                "/api/v1/open", headers={"X-Original-IP": BROWSER, "X-Real-IP": EDGE}
            )

    assert response.status_code == 200, response.text
    assert _completed(logs)["client_ip"] == EDGE
