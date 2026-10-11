from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from shared_auth_lib.dependencies.auth_dependencies import _AuthClientRegistry
from shared_auth_lib.middleware import install_standard_middleware
from shared_auth_lib.testing import Persona, async_signed_client

SECRET = "test-gateway-signing-secret"
REFUSING_REDIS = "redis://127.0.0.1:1/0"
NUL_BODY = b'{"description": "night\\u0000shift"}'
JSON = {"content-type": "application/json"}


class _Role(BaseModel):
    description: str


@pytest.fixture(autouse=True)
def _signing_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTH_LIB_GATEWAY_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("AUTH_LIB_DEV_MODE_BYPASS", "false")
    _AuthClientRegistry.reset()
    yield
    _AuthClientRegistry.reset()


def _app() -> FastAPI:
    app = FastAPI()

    @app.post("/api/v1/roles")
    async def create(role: _Role) -> dict:
        return {"description": role.description}

    install_standard_middleware(
        app,
        service_name="test-service",
        environment="test",
        cors=None,
        hmac_secret=SECRET,
        hmac_skip_paths=["/api/v1/health"],
        hmac_redis_url=REFUSING_REDIS,
    )
    return app


async def test_a_signed_request_with_unstorable_text_is_a_correlated_422() -> None:
    async with asyncio.timeout(10), async_signed_client(_app(), Persona()) as client:
        response = await client.post("/api/v1/roles", content=NUL_BODY, headers=JSON)

    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["fields"][0]["loc"] == ["body", "description"]
    assert error["correlation_id"] == response.headers["x-correlation-id"]


async def test_an_unsigned_request_meets_auth_before_its_text_is_judged() -> None:
    transport = ASGITransport(app=_app())
    async with (
        asyncio.timeout(10),
        AsyncClient(transport=transport, base_url="http://t") as c,
    ):
        response = await c.post("/api/v1/roles", content=NUL_BODY, headers=JSON)

    assert response.status_code == 403, response.text


async def test_a_signed_clean_body_still_reaches_the_route() -> None:
    async with asyncio.timeout(10), async_signed_client(_app(), Persona()) as client:
        response = await client.post(
            "/api/v1/roles", json={"description": "night \U0001f319"}
        )

    assert response.status_code == 200, response.text
    assert response.json() == {"description": "night \U0001f319"}
