"""L2.1: require_any_role validates against SystemRole at dependency-construction
time (router registration), not at request time.

`require_role` was removed in v0.16.0 — it resolved through the widening
`AuthContext.has_role` and had no callers fleet-wide. The construction-time
validation it carried lives on in `require_any_role`, which is the only
role-gating dependency now.
"""

import pytest

from shared_auth_lib.constants.roles import SystemRole
from shared_auth_lib.dependencies.auth_dependencies import require_any_role


def test_require_any_role_accepts_systemrole():
    require_any_role([SystemRole.ADMIN])


def test_require_any_role_accepts_valid_string():
    require_any_role(["admin"])


def test_require_any_role_accepts_super_admin():
    require_any_role([SystemRole.SUPER_ADMIN])
    require_any_role(["super_admin"])


def test_require_any_role_accepts_system_roles():
    require_any_role([SystemRole.SUPER_ADMIN, SystemRole.ADMIN])


def test_require_any_role_rejects_unknown_string():
    with pytest.raises(ValueError, match="manager"):
        require_any_role(["manager"])


def test_require_any_role_rejects_bad_entry():
    with pytest.raises(ValueError, match="manager"):
        require_any_role(["admin", "manager"])


def test_error_names_valid_set():
    with pytest.raises(ValueError, match="super_admin, admin"):
        require_any_role(["manager"])
