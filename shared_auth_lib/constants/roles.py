"""Canonical platform role names — the single source of truth.

Services use this enum, never inline role-string literals. These are the 9
SYSTEM roles; business/display roles are data, not members. Values match the
strings carried in AuthContext.roles (e.g. "ADMIN"), so PlatformRole.ADMIN is a
drop-in for require_role("ADMIN"). The eventual per-tenant custom-RBAC overhaul
keeps these names; only the resolution mechanism changes.
"""

from enum import StrEnum


class PlatformRole(StrEnum):
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    MANAGER = "MANAGER"
    SENIOR_AGENT = "SENIOR_AGENT"
    AGENT = "AGENT"
    JUNIOR_AGENT = "JUNIOR_AGENT"
    VIEWER = "VIEWER"
    CONTENT_CREATOR = "CONTENT_CREATOR"
    PHOTOGRAPHER = "PHOTOGRAPHER"


ADMIN_ROLES: frozenset[PlatformRole] = frozenset(
    {PlatformRole.SUPER_ADMIN, PlatformRole.ADMIN, PlatformRole.MANAGER}
)

AGENT_ROLES: frozenset[PlatformRole] = frozenset(
    {PlatformRole.SENIOR_AGENT, PlatformRole.AGENT, PlatformRole.JUNIOR_AGENT}
)

# Coarse seniority ordering (distinct ranks). Used for hierarchy comparisons.
ROLE_RANK: dict[PlatformRole, int] = {
    PlatformRole.SUPER_ADMIN: 100,
    PlatformRole.ADMIN: 90,
    PlatformRole.MANAGER: 80,
    PlatformRole.SENIOR_AGENT: 70,
    PlatformRole.AGENT: 60,
    PlatformRole.JUNIOR_AGENT: 50,
    PlatformRole.CONTENT_CREATOR: 40,
    PlatformRole.PHOTOGRAPHER: 30,
    PlatformRole.VIEWER: 10,
}
