"""Tests for DEV_MODE_BYPASS feature in shared-auth-lib.

Covers: settings activation, safety guard, the build_dev_auth_context
helper, per-request X-Dev-* overrides, and HMAC middleware short-circuit.
"""

import os
from unittest.mock import patch
from uuid import UUID

import pytest
from starlette.requests import Request
from starlette.testclient import TestClient

from shared_auth_lib._dev_headers import build_dev_auth_context
from shared_auth_lib.models.auth_context import AuthContext

_DEV_UUID = UUID("00000000-0000-0000-0000-000000000001")


def _make_request(headers: dict[str, str] | None = None) -> Request:
    """Construct a minimal Starlette Request for header-override tests."""
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


def _dev_env() -> dict[str, str]:
    return {
        "AUTH_LIB_GATEWAY_SIGNING_SECRET": "test-secret",
        "AUTH_LIB_ENVIRONMENT": "dev",
        "AUTH_LIB_DEV_MODE_BYPASS": "true",
    }


# ── Settings activation & safety guard ──


class TestDevBypassSettings:
    """Settings validator allows bypass only in dev environments."""

    def _build_settings(self, **overrides):
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
        assert self._build_settings().DEV_MODE_BYPASS is False

    def test_bypass_on_in_dev(self):
        s = self._build_settings(DEV_MODE_BYPASS="true", ENVIRONMENT="dev")
        assert s.DEV_MODE_BYPASS is True
        assert s.DEV_USER_ID == _DEV_UUID
        assert s.DEV_PERMISSIONS == ["*"]

    def test_bypass_on_in_development(self):
        s = self._build_settings(DEV_MODE_BYPASS="true", ENVIRONMENT="development")
        assert s.DEV_MODE_BYPASS is True

    def test_bypass_on_in_local(self):
        s = self._build_settings(DEV_MODE_BYPASS="true", ENVIRONMENT="local")
        assert s.DEV_MODE_BYPASS is True

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


# ── AuthContext builder: env defaults ──


class TestBuildDevAuthContextEnvDefaults:
    """Without a Request, the helper uses AUTH_LIB_DEV_* env vars."""

    def test_no_request_returns_env_defaults(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context()

        assert isinstance(ctx, AuthContext)
        assert ctx.user_id == _DEV_UUID
        assert ctx.tenant_id == _DEV_UUID
        assert ctx.roles == ["ADMIN"]
        assert ctx.permissions == ["*"]
        assert ctx.email == "dev@thinkrealty.local"
        assert ctx.auth_provider == "dev"
        assert ctx.is_active is True
        assert ctx.is_suspended is False
        get_settings.cache_clear()

    def test_explicit_correlation_id(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context(correlation_id="corr-abc-123")

        assert ctx.correlation_id == "corr-abc-123"
        get_settings.cache_clear()

    def test_custom_env_persona(self):
        custom_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        env = {
            **_dev_env(),
            "AUTH_LIB_DEV_USER_ID": custom_id,
            "AUTH_LIB_DEV_TENANT_ID": custom_id,
            "AUTH_LIB_DEV_EMAIL": "custom@test.local",
            "AUTH_LIB_DEV_ROLES": '["MANAGER"]',
            "AUTH_LIB_DEV_PERMISSIONS": '["listing:read","listing:update"]',
        }
        with patch.dict(os.environ, env, clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context()

        assert str(ctx.user_id) == custom_id
        assert ctx.email == "custom@test.local"
        assert ctx.roles == ["MANAGER"]
        assert ctx.permissions == ["listing:read", "listing:update"]
        get_settings.cache_clear()


# ── AuthContext builder: per-request X-Dev-* overrides ──


class TestBuildDevAuthContextHeaderOverrides:
    """Per-request X-Dev-* headers override env defaults for that request."""

    def test_roles_override(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context(
                _make_request({"X-Dev-Roles": "AGENT,MANAGER"})
            )

        assert ctx.roles == ["AGENT", "MANAGER"]
        # User ID stays at env default (no override sent)
        assert ctx.user_id == _DEV_UUID
        get_settings.cache_clear()

    def test_permissions_override(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context(
                _make_request({"X-Dev-Permissions": "listing:read,media:read"})
            )

        assert ctx.permissions == ["listing:read", "media:read"]
        get_settings.cache_clear()

    def test_tenant_override(self):
        custom_tenant = "11111111-2222-3333-4444-555555555555"
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context(
                _make_request({"X-Dev-Tenant-Id": custom_tenant})
            )

        assert str(ctx.tenant_id) == custom_tenant
        get_settings.cache_clear()

    def test_email_override(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context(
                _make_request({"X-Dev-Email": "agent@test.local"})
            )

        assert ctx.email == "agent@test.local"
        get_settings.cache_clear()

    def test_invalid_uuid_falls_back_to_env(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context(
                _make_request({"X-Dev-User-Id": "not-a-uuid"})
            )

        assert ctx.user_id == _DEV_UUID
        get_settings.cache_clear()

    def test_empty_csv_falls_back_to_env(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            # Empty and whitespace-only entries → no valid items → env default
            ctx = build_dev_auth_context(
                _make_request({"X-Dev-Permissions": " , , "})
            )

        assert ctx.permissions == ["*"]
        get_settings.cache_clear()

    def test_correlation_id_from_header(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context(
                _make_request({"X-Correlation-Id": "abc-123"})
            )

        assert ctx.correlation_id == "abc-123"
        get_settings.cache_clear()

    def test_explicit_correlation_id_beats_header(self):
        with patch.dict(os.environ, _dev_env(), clear=False):
            from shared_auth_lib.config import get_settings

            get_settings.cache_clear()
            ctx = build_dev_auth_context(
                request=_make_request({"X-Correlation-Id": "abc-123"}),
                correlation_id="explicit-999",
            )

        assert ctx.correlation_id == "explicit-999"
        get_settings.cache_clear()


# ── AuthContextClient short-circuit ──


class TestAuthContextClientBypass:
    """AuthContextClient returns canned AuthContext when bypass is on."""

    @pytest.mark.asyncio
    async def test_short_circuits_http_call(self):
        env = {
            **_dev_env(),
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
                ctx = await client.get_auth_context(
                    external_auth_id=_DEV_UUID,
                    correlation_id="corr-123",
                )
                assert isinstance(ctx, AuthContext)
                assert ctx.user_id == _DEV_UUID
                assert ctx.auth_provider == "dev"
                assert ctx.correlation_id == "corr-123"
                # Wildcard satisfies any require_permission check
                assert "*" in ctx.permissions
            finally:
                await client.close()
                get_settings.cache_clear()


# ── HMAC middleware short-circuit ──


class TestHMACMiddlewareBypass:
    """HMAC middleware skips verification when bypass is on."""

    def _make_app(self, dev_mode_bypass: bool):
        from fastapi import FastAPI

        from shared_auth_lib.middleware.hmac_middleware import (
            GatewayHMACMiddleware,
        )

        app = FastAPI()
        app.add_middleware(
            GatewayHMACMiddleware,
            secret="test-secret",
            dev_mode_bypass=dev_mode_bypass,
        )

        @app.get("/api/v1/test")
        async def test_endpoint():
            return {"status": "ok"}

        return app

    def test_bypass_allows_unsigned_request(self):
        client = TestClient(self._make_app(dev_mode_bypass=True))
        response = client.get("/api/v1/test")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_no_bypass_rejects_unsigned_request(self):
        client = TestClient(self._make_app(dev_mode_bypass=False))
        response = client.get("/api/v1/test")
        assert response.status_code == 403
