"""L2.1: require_role / require_any_role validate against SystemRole at
dependency-construction time (router registration), not at request time."""

import pytest

from shared_auth_lib.constants.roles import SystemRole
from shared_auth_lib.dependencies.auth_dependencies import (
    require_any_role,
    require_role,
)


def test_require_role_accepts_systemrole():
    require_role(SystemRole.ADMIN)


def test_require_role_accepts_valid_string():
    require_role("admin")


def test_require_role_accepts_super_admin():
    require_role(SystemRole.SUPER_ADMIN)
    require_role("super_admin")


def test_require_role_rejects_unknown_string():
    with pytest.raises(ValueError, match="manager"):
        require_role("manager")


def test_require_any_role_accepts_system_roles():
    require_any_role([SystemRole.SUPER_ADMIN, SystemRole.ADMIN])


def test_require_any_role_rejects_bad_entry():
    with pytest.raises(ValueError, match="manager"):
        require_any_role(["admin", "manager"])


def test_require_role_error_names_valid_set():
    with pytest.raises(ValueError, match="super_admin, admin"):
        require_role("manager")
