# tests/test_roles.py
import pytest

from shared_auth_lib.constants.roles import (
    ADMIN_ROLES,
    AGENT_ROLES,
    ROLE_RANK,
    PlatformRole,
)

EXPECTED = {
    "SUPER_ADMIN", "ADMIN", "MANAGER", "SENIOR_AGENT", "AGENT",
    "JUNIOR_AGENT", "VIEWER", "CONTENT_CREATOR", "PHOTOGRAPHER",
}


def test_platform_role_has_exactly_9_members():
    assert {r.value for r in PlatformRole} == EXPECTED
    assert len(list(PlatformRole)) == 9


def test_tenant_admin_is_not_a_role():
    with pytest.raises(ValueError):
        PlatformRole("TENANT_ADMIN")


def test_role_is_a_str_enum_for_drop_in_use():
    assert PlatformRole.ADMIN == "ADMIN"
    assert isinstance(PlatformRole.ADMIN, str)


def test_admin_and_agent_groups():
    assert ADMIN_ROLES == frozenset(
        {PlatformRole.SUPER_ADMIN, PlatformRole.ADMIN, PlatformRole.MANAGER}
    )
    assert AGENT_ROLES == frozenset(
        {PlatformRole.SENIOR_AGENT, PlatformRole.AGENT, PlatformRole.JUNIOR_AGENT}
    )


def test_role_rank_is_total_and_strictly_ordered():
    assert set(ROLE_RANK) == set(PlatformRole)  # every role ranked
    ranks = list(ROLE_RANK.values())
    assert len(set(ranks)) == len(ranks)  # strictly ordered (distinct)
    assert ROLE_RANK[PlatformRole.SUPER_ADMIN] == max(ranks)


def test_role_and_authz_symbols_exported_at_top_level():
    from shared_auth_lib import (  # noqa: F401
        ADMIN_ROLES,
        AGENT_ROLES,
        ROLE_RANK,
        PlatformRole,
        can,
        require_capability,
    )

    assert PlatformRole.ADMIN == "ADMIN"
    assert callable(can)
    assert callable(require_capability)
