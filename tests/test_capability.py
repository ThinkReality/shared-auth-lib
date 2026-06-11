# tests/test_capability.py
from uuid import UUID

import pytest
from tr_shared.exceptions import AuthorizationError

from shared_auth_lib.authz.capability import can, require_capability
from shared_auth_lib.models.auth_context import AuthContext

_UID = UUID("11111111-1111-1111-1111-111111111111")


def _ctx(permissions: list[str]) -> AuthContext:
    return AuthContext(
        external_auth_id=_UID,
        user_id=_UID,
        email="x@example.com",
        tenant_id=_UID,
        permissions=permissions,
    )


def test_can_delegates_to_has_permission():
    ctx = _ctx(["lead:edit"])
    assert can(ctx, "lead:edit") is True
    assert can(ctx, "lead:delete") is False


def test_can_accepts_and_ignores_resource_today():
    ctx = _ctx(["lead:edit"])
    assert can(ctx, "lead:edit", resource={"owner_id": "someone"}) is True


def test_can_honours_wildcard_permission():
    ctx = _ctx(["*"])
    assert can(ctx, "anything:goes") is True


async def test_require_capability_allows_with_permission():
    ctx = _ctx(["lead:edit"])
    checker = require_capability("lead:edit")
    assert await checker(auth_context=ctx) is ctx


async def test_require_capability_denies_without_permission():
    ctx = _ctx([])
    checker = require_capability("lead:edit")
    with pytest.raises(AuthorizationError) as exc:
        await checker(auth_context=ctx)
    assert exc.value.status_code == 403
