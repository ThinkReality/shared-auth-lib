"""Tests for DEV_MODE_BYPASS feature in shared-auth-lib.

Covers: settings activation, safety guard, header injection,
AuthContext short-circuit, and per-request overrides.
"""

import os
from unittest.mock import patch
from uuid import UUID

import pytest
from starlette.testclient import TestClient

from shared_auth_lib._dev_headers import build_dev_identity
from shared_auth_lib.models.auth_context import AuthContext, GatewayIdentityHeaders

_DEV_UUID = UUID("00000000-0000-0000-0000-000000000001")


# ── Settings activation & safety guard ──


class TestDevBypassSettings:
    """Settings validator allows bypass only in dev environments."""

    def _build_settings(self, **overrides):
        """Build AuthLibSettings with test defaults + overrides."""
        from shared_auth_lib.config import AuthLibSettings

        env = {
            "AUTH_LIB_GATEWAY_SIGNING_SECRET": "test-secret",
            "AUTH_LIB_ENVIRONMENT": "dev",
            "AUTH_LIB_DEV_MODE_BYPASS": "false",
            **{f"AUTH_LIB_{k}": str(v) for k, v in overrides.items()},
        }
        with patch.dict(os.environ, env, clear=False):
            return AuthLibSettings()

    def test_bypass_off_by_default(self):
        settings = self._build_settings()
        assert settings.DEV_MODE_BYPASS is False

    def test_bypass_on_in_dev(self):
        settings = self._build_settings(
            DEV_MODE_BYPASS="true", ENVIRONMENT="dev"
        )
        assert settings.DEV_MODE_BYPASS is True
        assert settings.DEV_USER_ID == _DEV_UUID
        assert settings.DEV_PERMISSIONS == ["*"]

    def test_bypass_on_in_development(self):
        settings = self._build_settings(
            DEV_MODE_BYPASS="true", ENVIRONMENT="development"
        )
        assert settings.DEV_MODE_BYPASS is True

    def test_bypass_on_in_local(self):
        settings = self._build_settings(
            DEV_MODE_BYPASS="true", ENVIRONMENT="local"
        )
        assert settings.DEV_MODE_BYPASS is True

    def test_bypass_rejected_in_production(self):
        with pytest.raises(ValueError, match="safety guard"):
            self._build_settings(
                DEV_MODE_BYPASS="true",
                ENVIRONMENT="production",
                SERVICE_TOKEN="real-token",
                CRM_BACKEND_URL="http://crm-backend:8000",
            )

    def test_bypass_rejected_in_staging(self):
        with pytest.raises(ValueError, match="safety guard"):
            self._build_settings(
                DEV_MODE_BYPASS="true",
                ENVIRONMENT="staging",
                SERVICE_TOKEN="real-token",
                CRM_BACKEND_URL="http://crm-backend:8000",
            )

    def test_custom_dev_persona(self):
        custom_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        settings = self._build_settings(
            DEV_MODE_BYPASS="true",
            ENVIRONMENT="dev",
            DEV_USER_ID=custom_id,
            DEV_TENANT_ID=custom_id,
            DEV_EMAIL="custom@test.local",
        )
        assert str(settings.DEV_USER_ID) == custom_id
        assert settings.DEV_EMAIL == "custom@test.local"


# ── Identity builder ──


class TestDevIdentity:
    """build_dev_identity returns the right GatewayIdentityHeaders."""

    def _request(self, headers: dict[str, str] | None = None):
        from starlette.requests import Request

        header_list = [(b"host", b"localhost")]
        if headers:
            for k, v in headers.items():
                header_list.append((k.lower().encode(), v.encode()))
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/test",
            "headers": header_list,
            "query_string": b"",
        }
        return Request(scope)

    def _with_settings(self):
        return patch.dict(
            os.environ,
            {
                "AUTH_LIB_GATEWAY_SIGNING_SECRET": "test-secret",
                "AUTH_LIB_ENVIRONMENT": "dev",
                "AUTH_LIB_DEV_MODE_BYPASS": "true",
            },
            clear=False,
        )

    def test_default_identity(self):
        with self._with_settings():
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            identity = build_dev_identity(self._request())

        assert isinstance(identity, GatewayIdentityHeaders)
        assert identity.user_id == _DEV_UUID
        assert identity.tenant_id == _DEV_UUID
        assert identity.user_role == "ADMIN"
        assert identity.auth_provider == "dev"

    def test_request_header_overrides(self):
        custom_tenant = "11111111-2222-3333-4444-555555555555"
        with self._with_settings():
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            identity = build_dev_identity(
                self._request(
                    {
                        "X-Dev-Tenant-Id": custom_tenant,
                        "X-Dev-Roles": "AGENT,MANAGER",
                    }
                )
            )

        assert str(identity.tenant_id) == custom_tenant
        assert identity.user_role == "AGENT"
        assert identity.user_id == _DEV_UUID  # unchanged

    def test_invalid_override_uuid_falls_back(self):
        with self._with_settings():
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            identity = build_dev_identity(
                self._request({"X-Dev-User-Id": "not-a-uuid"})
            )

        # Invalid UUID silently falls back to env default
        assert identity.user_id == _DEV_UUID


# ── AuthContext canned response ──


class TestAuthContextBypass:
    """AuthContextClient returns canned AuthContext when bypass is on."""

    @pytest.mark.asyncio
    async def test_returns_canned_context(self):
        env = {
            "AUTH_LIB_GATEWAY_SIGNING_SECRET": "test-secret",
            "AUTH_LIB_ENVIRONMENT": "dev",
            "AUTH_LIB_DEV_MODE_BYPASS": "true",
            "AUTH_LIB_CRM_BACKEND_URL": "http://crm-backend:8000",
            "AUTH_LIB_SERVICE_TOKEN": "test-token",
        }
        with patch.dict(os.environ, env, clear=False):
            # Clear lru_cache so new env vars take effect
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()

            from shared_auth_lib.services.auth_context_client import (
                AuthContextClient,
            )

            client = AuthContextClient(
                crm_backend_url="http://crm-backend:8000",
                service_token="test-token",
            )
            try:
                ctx = await client.get_auth_context(
                    external_auth_id=_DEV_UUID,
                    correlation_id="test-corr-123",
                )

                assert isinstance(ctx, AuthContext)
                assert ctx.user_id == _DEV_UUID
                assert ctx.tenant_id == _DEV_UUID
                assert ctx.permissions == ["*"]
                assert ctx.roles == ["ADMIN"]
                assert ctx.is_active is True
                assert ctx.is_suspended is False
                assert ctx.auth_provider == "dev"
                assert ctx.correlation_id == "test-corr-123"
            finally:
                await client.close()
                get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_wildcard_satisfies_any_permission(self):
        env = {
            "AUTH_LIB_GATEWAY_SIGNING_SECRET": "test-secret",
            "AUTH_LIB_ENVIRONMENT": "dev",
            "AUTH_LIB_DEV_MODE_BYPASS": "true",
            "AUTH_LIB_CRM_BACKEND_URL": "http://crm-backend:8000",
            "AUTH_LIB_SERVICE_TOKEN": "test-token",
        }
        with patch.dict(os.environ, env, clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()

            from shared_auth_lib.services.auth_context_client import (
                AuthContextClient,
            )

            client = AuthContextClient(
                crm_backend_url="http://crm-backend:8000",
                service_token="test-token",
            )
            try:
                ctx = await client.get_auth_context(_DEV_UUID)
                # Wildcard "*" is in the permissions list
                assert "*" in ctx.permissions
            finally:
                await client.close()
                get_settings.cache_clear()


# ── HMAC middleware integration ──


class TestHMACMiddlewareBypass:
    """HMAC middleware skips verification when bypass is on."""

    def _make_app(self):
        from fastapi import FastAPI

        from shared_auth_lib.middleware.hmac_middleware import (
            GatewayHMACMiddleware,
        )

        app = FastAPI()
        app.add_middleware(
            GatewayHMACMiddleware,
            secret="test-secret",
            dev_mode_bypass=True,
        )

        @app.get("/api/v1/test")
        async def test_endpoint():
            return {"status": "ok"}

        return app

    def test_request_without_signature_succeeds(self):
        app = self._make_app()
        client = TestClient(app)
        # No X-Gateway-Signature, no X-Gateway-Timestamp — normally 403
        response = client.get("/api/v1/test")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_bypass_off_rejects_unsigned_request(self):
        from fastapi import FastAPI

        from shared_auth_lib.middleware.hmac_middleware import (
            GatewayHMACMiddleware,
        )

        app = FastAPI()
        app.add_middleware(
            GatewayHMACMiddleware,
            secret="test-secret",
            dev_mode_bypass=False,
        )

        @app.get("/api/v1/test")
        async def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app)
        response = client.get("/api/v1/test")
        assert response.status_code == 403
