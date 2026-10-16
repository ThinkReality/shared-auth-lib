from uuid import uuid4

import pytest

from shared_auth_lib.authz.capability import require_capability
from shared_auth_lib.dependencies.auth_dependencies import require_permission
from shared_auth_lib.models.auth_context import AuthContext, permission_granted
from shared_auth_lib.permissions import LEAD_VIEW


def _ctx(permissions: list[str]) -> AuthContext:
    return AuthContext(
        external_auth_id=uuid4(),
        user_id=uuid4(),
        email="u@x.com",
        tenant_id=uuid4(),
        permissions=permissions,
    )


@pytest.mark.parametrize("factory", [require_permission, require_capability])
def test_a_gate_on_an_unregistered_permission_fails_at_construction(factory):
    with pytest.raises(ValueError, match="'lead:raed'"):
        factory("lead:raed")


@pytest.mark.parametrize("factory", [require_permission, require_capability])
def test_a_gate_on_a_registered_permission_builds(factory):
    assert factory(LEAD_VIEW)._required_permissions == (LEAD_VIEW,)


def test_has_permission_rejects_an_unregistered_permission():
    with pytest.raises(ValueError, match="'lead:raed'"):
        _ctx(["*"]).has_permission("lead:raed")


def test_has_permission_answers_for_a_registered_permission():
    assert _ctx([LEAD_VIEW]).has_permission(LEAD_VIEW) is True
    assert _ctx([]).has_permission(LEAD_VIEW) is False


def test_permission_granted_matches_any_name_it_is_asked_about():
    assert permission_granted(["*"], "not:in:the_catalog") is True
