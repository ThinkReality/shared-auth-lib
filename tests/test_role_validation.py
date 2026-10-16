"""L2.1: require_any_role validates against SystemRole at dependency-construction
time (router registration), not at request time.

`require_role` was removed in v0.16.0 — it resolved through the widening
`AuthContext.has_role` and had no callers fleet-wide. The construction-time
validation it carried lives on in `require_any_role`, which is the only
role-gating dependency now.
"""

from uuid import uuid4

import pytest

from shared_auth_lib.constants.roles import SystemRole
from shared_auth_lib.dependencies.auth_dependencies import require_any_role
from shared_auth_lib.models.auth_context import AuthContext


def _ctx(roles: list[str]) -> AuthContext:
    return AuthContext(
        external_auth_id=uuid4(),
        user_id=uuid4(),
        email="u@x.com",
        tenant_id=uuid4(),
        roles=roles,
    )


def test_require_any_role_accepts_system_roles():
    gate = require_any_role([SystemRole.SUPER_ADMIN, SystemRole.ADMIN])
    assert gate._required_permissions == ("super_admin", "admin")


@pytest.mark.parametrize("role", ["admin", "manager"])
def test_require_any_role_rejects_a_bare_string(role):
    with pytest.raises(TypeError, match=repr(role)):
        require_any_role([SystemRole.ADMIN, role])


@pytest.mark.parametrize("role", ["admin", "manager"])
def test_has_any_role_rejects_a_bare_string(role):
    with pytest.raises(TypeError, match=repr(role)):
        _ctx(["admin"]).has_any_role([role])


def test_has_any_role_matches_a_held_system_role():
    assert _ctx(["sales_agent", "admin"]).has_any_role([SystemRole.ADMIN]) is True
    assert _ctx(["sales_agent"]).has_any_role(list(SystemRole)) is False


def test_error_names_the_members():
    with pytest.raises(TypeError, match="SystemRole.SUPER_ADMIN, SystemRole.ADMIN"):
        require_any_role(["manager"])
