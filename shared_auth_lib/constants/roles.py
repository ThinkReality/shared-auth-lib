"""Canonical platform SYSTEM roles — the single source of truth.

Only two platform-fixed roles exist: ``super_admin`` and ``admin`` (lowercase).
Every other role is a per-tenant DYNAMIC role stored as data (``auth_roles``),
never a member here. Values are lowercase and match the strings carried in
``AuthContext.roles`` on the wire. A role NAME is checked in exactly one place —
tenant scope (``has_role(SystemRole.SUPER_ADMIN)``); all feature access is
permission-based.
"""

from enum import StrEnum


class SystemRole(StrEnum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"


# The platform-admin tier. Membership == tenant-admin / control-plane access.
# Replaces the old ADMIN_ROLES (which wrongly included the now-dynamic MANAGER).
SYSTEM_ROLES: frozenset[SystemRole] = frozenset(SystemRole)
