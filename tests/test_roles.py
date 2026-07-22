# tests/test_roles.py
import pytest

from shared_auth_lib.constants.roles import SYSTEM_ROLES, SystemRole


def test_system_role_has_exactly_2_members():
    assert {r for r in SystemRole} == {
        SystemRole.SUPER_ADMIN,
        SystemRole.ADMIN,
    }
    assert len(list(SystemRole)) == 2


def test_system_role_values_are_lowercase():
    assert SystemRole.SUPER_ADMIN == "super_admin"
    assert SystemRole.ADMIN == "admin"


def test_role_is_a_str_enum_for_drop_in_use():
    assert SystemRole.ADMIN == "admin"
    assert isinstance(SystemRole.ADMIN, str)


def test_system_roles_frozenset():
    assert SYSTEM_ROLES == frozenset({SystemRole.SUPER_ADMIN, SystemRole.ADMIN})


def test_manager_and_agent_are_not_system_roles():
    with pytest.raises(ValueError):
        SystemRole("MANAGER")
    with pytest.raises(ValueError):
        SystemRole("AGENT")


def test_top_level_exports_resolve():
    from shared_auth_lib import SYSTEM_ROLES, SystemRole  # noqa: F401

    assert SystemRole.ADMIN == "admin"
    assert SYSTEM_ROLES == frozenset({SystemRole.SUPER_ADMIN, SystemRole.ADMIN})


def test_removed_symbols_are_gone():
    import shared_auth_lib

    assert not hasattr(shared_auth_lib, "PlatformRole")
    assert not hasattr(shared_auth_lib, "ADMIN_ROLES")
    assert not hasattr(shared_auth_lib, "AGENT_ROLES")
    assert not hasattr(shared_auth_lib, "ROLE_RANK")
