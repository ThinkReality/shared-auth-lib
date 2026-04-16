"""Tests for DEV_MODE_BYPASS feature in shared-auth-lib.

Covers: settings activation, safety guard, header injection,
AuthContext short-circuit, and per-request overrides.
"""

import os
from unittest.mock import patch
from uuid import UUID

import pytest
from starlette.testclient import TestClient

from shared_auth_lib._dev_headers import build_dev_headers
from shared_auth_lib.models.auth_context import AuthContext

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


# ── Header injection ──


class TestDevHeaders:
    """build_dev_headers injects the right ASGI headers."""

    def _make_settings(self):
        from shared_auth_lib.config import AuthLibSettings

        env = {
            "AUTH_LIB_GATEWAY_SIGNING_SECRET": "test-secret",
            "AUTH_LIB_ENVIRONMENT": "dev",
            "AUTH_LIB_DEV_MODE_BYPASS": "true",
        }
        with patch.dict(os.environ, env, clear=False):
            return AuthLibSettings()

    def test_injects_identity_headers(self):
        settings = self._make_settings()
        original = [(b"host", b"localhost")]
        result = build_dev_headers(original, settings)

        headers_dict = {k: v for k, v in result}
        assert headers_dict[b"x-user-id"] == str(_DEV_UUID).encode()
        assert headers_dict[b"x-tenant-id"] == str(_DEV_UUID).encode()
        assert headers_dict[b"x-user-role"] == b"ADMIN"
        assert headers_dict[b"x-auth-provider"] == b"dev"
        # Original headers preserved
        assert headers_dict[b"host"] == b"localhost"

    def test_request_override_headers(self):
        settings = self._make_settings()
        custom_tenant = "11111111-2222-3333-4444-555555555555"
        original = [
            (b"host", b"localhost"),
            (b"x-dev-tenant-id", custom_tenant.encode()),
            (b"x-dev-roles", b"AGENT"),
        ]
        result = build_dev_headers(original, settings)

        headers_dict = {k: v for k, v in result}
        # Tenant overridden by X-Dev-Tenant-Id header
        assert headers_dict[b"x-tenant-id"] == custom_tenant.encode()
        # Role overridden by X-Dev-Roles header
        assert headers_dict[b"x-user-role"] == b"AGENT"
        # User ID stays at default (no override sent)
        assert headers_dict[b"x-user-id"] == str(_DEV_UUID).encode()

    def test_strips_conflicting_originals(self):
        settings = self._make_settings()
        original = [
            (b"x-user-id", b"attacker-injected"),
            (b"host", b"localhost"),
        ]
        result = build_dev_headers(original, settings)

        user_ids = [v for k, v in result if k == b"x-user-id"]
        assert len(user_ids) == 1
        assert user_ids[0] == str(_DEV_UUID).encode()


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
