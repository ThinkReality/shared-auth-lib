"""Tests for AuthContextClient."""

from uuid import uuid4

import httpx
import pytest
from tr_shared.http.circuit_breaker import CircuitState

from shared_auth_lib.exceptions import AuthContextNotFoundError
from shared_auth_lib.services.auth_context_client import (
    AuthContextClient,
)

USER_ID = uuid4()
TENANT_ID = uuid4()
INTERNAL_USER_ID = uuid4()

VALID_RESPONSE = {
    "external_auth_id": str(USER_ID),
    "user_id": str(INTERNAL_USER_ID),
    "email": "test@thinkrealty.ae",
    "tenant_id": str(TENANT_ID),
    "roles": ["ADMIN"],
    "permissions": ["user:read", "listing:create"],
    "is_active": True,
    "is_suspended": False,
    "role_hierarchy": ["ADMIN", "MANAGER", "AGENT"],
    "auth_provider": "supabase",
}


@pytest.fixture
def mock_transport_ok():
    return httpx.MockTransport(
        lambda request: httpx.Response(
            200, json=VALID_RESPONSE
        )
    )


@pytest.fixture
def mock_transport_404():
    return httpx.MockTransport(
        lambda request: httpx.Response(
            404, json={"detail": "not found"}
        )
    )


@pytest.fixture
def mock_transport_500():
    return httpx.MockTransport(
        lambda request: httpx.Response(
            500, json={"detail": "internal error"}
        )
    )


def _make_client(transport: httpx.MockTransport) -> AuthContextClient:
    client = AuthContextClient(
        crm_backend_url="http://crm-backend:8000",
        service_token="test-token",
        timeout=5.0,
    )
    client._client = httpx.AsyncClient(
        base_url="http://crm-backend:8000",
        transport=transport,
    )
    return client


class TestAuthContextClient:
    @pytest.mark.asyncio
    async def test_successful_fetch(self, mock_transport_ok):
        client = _make_client(mock_transport_ok)
        try:
            ctx = await client.get_auth_context(USER_ID)
            assert ctx.external_auth_id == USER_ID
            assert ctx.user_id == INTERNAL_USER_ID
            assert ctx.email == "test@thinkrealty.ae"
            assert ctx.tenant_id == TENANT_ID
            assert "ADMIN" in ctx.roles
            assert ctx.is_active is True
            assert ctx.is_suspended is False
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_404_raises_not_found(
        self, mock_transport_404
    ):
        client = _make_client(mock_transport_404)
        try:
            with pytest.raises(AuthContextNotFoundError):
                await client.get_auth_context(USER_ID)
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_500_raises_not_found(
        self, mock_transport_500
    ):
        client = _make_client(mock_transport_500)
        try:
            with pytest.raises(AuthContextNotFoundError):
                await client.get_auth_context(USER_ID)
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_timeout_raises_not_found(self):
        def raise_timeout(request):
            raise httpx.ReadTimeout(
                "timed out", request=request
            )

        transport = httpx.MockTransport(raise_timeout)
        client = _make_client(transport)
        try:
            with pytest.raises(AuthContextNotFoundError):
                await client.get_auth_context(USER_ID)
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_service_token_sent_in_header(self):
        captured_headers = {}

        def capture_request(request):
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json=VALID_RESPONSE)

        transport = httpx.MockTransport(capture_request)
        client = _make_client(transport)
        try:
            await client.get_auth_context(USER_ID)
            assert (
                captured_headers.get("x-service-token")
                == "test-token"
            )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_correct_url_called(self):
        captured_url = None

        def capture_request(request):
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(200, json=VALID_RESPONSE)

        transport = httpx.MockTransport(capture_request)
        client = _make_client(transport)
        try:
            await client.get_auth_context(USER_ID)
            assert f"/internal/auth-context/{USER_ID}" in captured_url
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_close_is_idempotent(
        self, mock_transport_ok
    ):
        client = _make_client(mock_transport_ok)
        await client.close()
        await client.close()


class TestCircuitBreaker:
    """Circuit breaker behaviour inside AuthContextClient."""

    def _make_failing_client(self) -> AuthContextClient:
        transport = httpx.MockTransport(
            lambda req: httpx.Response(500, json={"detail": "error"})
        )
        client = AuthContextClient(
            crm_backend_url="http://crm-backend:8000",
            service_token="test-token",
            circuit_failure_threshold=3,
            circuit_recovery_timeout=30,
        )
        client._client = httpx.AsyncClient(
            base_url="http://crm-backend:8000",
            transport=transport,
        )
        return client

    @pytest.mark.asyncio
    async def test_circuit_opens_after_threshold_failures(self):
        """After N 5xx failures the circuit should be open."""
        client = self._make_failing_client()
        try:
            for _ in range(3):
                with pytest.raises(AuthContextNotFoundError):
                    await client.get_auth_context(USER_ID)
            assert client._circuit.state == CircuitState.OPEN
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_open_circuit_skips_http_call(self):
        """When the circuit is open no HTTP request should be made."""
        call_count = 0

        def counting_transport(req):
            nonlocal call_count
            call_count += 1
            return httpx.Response(500, json={})

        client = AuthContextClient(
            crm_backend_url="http://crm-backend:8000",
            service_token="test-token",
            circuit_failure_threshold=1,
            circuit_recovery_timeout=9999,
        )
        client._client = httpx.AsyncClient(
            base_url="http://crm-backend:8000",
            transport=httpx.MockTransport(counting_transport),
        )
        try:
            # First call: triggers failure and opens circuit (1 HTTP call)
            with pytest.raises(AuthContextNotFoundError):
                await client.get_auth_context(USER_ID)
            # Second call: circuit is open, no HTTP call should be made
            with pytest.raises(AuthContextNotFoundError):
                await client.get_auth_context(USER_ID)
            assert call_count == 1  # only the first call hit the network
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_circuit_closes_on_success_in_half_open(self):
        """A successful probe in half-open state closes the circuit."""
        responses = [
            httpx.Response(500, json={}),   # opens circuit
            httpx.Response(200, json=VALID_RESPONSE),  # probe succeeds
        ]
        idx = 0

        def sequential(req):
            nonlocal idx
            resp = responses[idx]
            idx += 1
            return resp

        client = AuthContextClient(
            crm_backend_url="http://crm-backend:8000",
            service_token="test-token",
            circuit_failure_threshold=1,
            circuit_recovery_timeout=0,  # immediately half-open
        )
        client._client = httpx.AsyncClient(
            base_url="http://crm-backend:8000",
            transport=httpx.MockTransport(sequential),
        )
        try:
            with pytest.raises(AuthContextNotFoundError):
                await client.get_auth_context(USER_ID)  # opens circuit
            # Wait is not needed because recovery_timeout=0
            ctx = await client.get_auth_context(USER_ID)  # probe succeeds
            assert ctx.external_auth_id == USER_ID
            assert client._circuit.state == CircuitState.CLOSED
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_circuit_stays_open_on_probe_failure(self):
        """A failed probe in half-open state keeps the circuit open."""
        client = AuthContextClient(
            crm_backend_url="http://crm-backend:8000",
            service_token="test-token",
            circuit_failure_threshold=1,
            circuit_recovery_timeout=0,
        )
        client._client = httpx.AsyncClient(
            base_url="http://crm-backend:8000",
            transport=httpx.MockTransport(
                lambda req: httpx.Response(500, json={})
            ),
        )
        try:
            with pytest.raises(AuthContextNotFoundError):
                await client.get_auth_context(USER_ID)  # opens circuit
            with pytest.raises(AuthContextNotFoundError):
                await client.get_auth_context(USER_ID)  # probe fails → stays open
            assert client._circuit.state == CircuitState.OPEN
        finally:
            await client.close()
