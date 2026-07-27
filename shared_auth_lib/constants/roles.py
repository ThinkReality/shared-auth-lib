"""Canonical platform SYSTEM roles — the single source of truth.

Only two platform-fixed roles exist: ``super_admin`` and ``admin`` (lowercase).
Every other role is a per-tenant DYNAMIC role stored as data (``auth_roles``),
never a member here. Values are lowercase and match the strings carried in
``AuthContext.roles`` on the wire.

Both system roles are **per-tenant**: ``auth_roles.tenant_id`` is NOT NULL, so
every tenant owns its own ``super_admin`` row. Neither name confers cross-tenant
scope, and a role name must never be used to widen tenant scope — every request
is scoped to ``AuthContext.tenant_id``. All feature access is permission-based.
The one intra-tenant distinction: only a ``super_admin`` may assign the
``super_admin`` role.
"""

from enum import StrEnum


class SystemRole(StrEnum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"


# The two platform-fixed role names. Membership == tenant-administrator rights
# WITHIN the caller's own tenant — never control-plane or cross-tenant access.
# Replaces the old ADMIN_ROLES (which wrongly included the now-dynamic MANAGER).
SYSTEM_ROLES: frozenset[SystemRole] = frozenset(SystemRole)
