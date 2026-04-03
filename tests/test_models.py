"""Tests for AuthContext and GatewayIdentityHeaders models."""

from uuid import UUID, uuid4

import pytest

from shared_auth_lib.models.auth_context import (
    AuthContext,
    GatewayIdentityHeaders,
)


class TestAuthContext:
    def _make_context(self, **overrides):
        defaults = dict(
            external_auth_id=uuid4(),
            user_id=uuid4(),
            email="test@thinkrealty.ae",
            tenant_id=uuid4(),
            roles=["ADMIN", "AGENT"],
            permissions=["user:read", "listing:create"],
            is_active=True,
            is_suspended=False,
            role_hierarchy=["ADMIN", "MANAGER", "AGENT"],
        )
        defaults.update(overrides)
        return AuthContext(**defaults)

    def test_has_permission_true(self):
        ctx = self._make_context()
        assert ctx.has_permission("user:read") is True

    def test_has_permission_false(self):
        ctx = self._make_context()
        assert ctx.has_permission("user:delete") is False

    def test_has_role_direct(self):
        ctx = self._make_context()
        assert ctx.has_role("ADMIN") is True

    def test_has_role_via_hierarchy(self):
        ctx = self._make_context(roles=["AGENT"])
        assert ctx.has_role("MANAGER") is True

    def test_has_role_missing(self):
        ctx = self._make_context(
            roles=["AGENT"], role_hierarchy=["AGENT"]
        )
        assert ctx.has_role("SUPER_ADMIN") is False

    def test_has_any_role_true(self):
        ctx = self._make_context()
        assert ctx.has_any_role(["VIEWER", "ADMIN"]) is True

    def test_has_any_role_false(self):
        ctx = self._make_context(roles=["AGENT"])
        assert (
            ctx.has_any_role(["SUPER_ADMIN", "OWNER"]) is False
        )

    def test_ensure_list_validator_with_none(self):
        ctx = self._make_context(roles=None, permissions=None)
        assert ctx.roles == []
        assert ctx.permissions == []

    def test_ensure_list_validator_with_string(self):
        ctx = self._make_context(
            roles="not-a-list", permissions="also-not"
        )
        assert ctx.roles == []
        assert ctx.permissions == []

    def test_all_fields_serializable(self):
        ctx = self._make_context()
        data = ctx.model_dump()
        assert isinstance(data["external_auth_id"], UUID)
        assert isinstance(data["user_id"], UUID)
        assert isinstance(data["tenant_id"], UUID)
        assert isinstance(data["roles"], list)
        assert isinstance(data["permissions"], list)


class TestGatewayIdentityHeaders:
    def test_defaults_are_none(self):
        headers = GatewayIdentityHeaders()
        assert headers.user_id is None
        assert headers.user_role is None
        assert headers.user_email is None
        assert headers.auth_provider is None
        assert headers.correlation_id is None
        assert headers.gateway_signature is None
        assert headers.gateway_timestamp is None

    def test_valid_uuid_accepted(self):
        uid = uuid4()
        headers = GatewayIdentityHeaders(user_id=uid)
        assert headers.user_id == uid

    def test_string_uuid_accepted(self):
        uid = uuid4()
        headers = GatewayIdentityHeaders(
            user_id=str(uid)
        )
        assert headers.user_id == uid

    def test_invalid_uuid_rejected(self):
        with pytest.raises(Exception):
            GatewayIdentityHeaders(user_id="not-a-uuid")
