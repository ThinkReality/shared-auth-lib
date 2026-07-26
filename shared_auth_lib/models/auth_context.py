from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _grant_matches(granted: str, required: str) -> bool:
    # Trailing colon kept in prefix so ``lead:*`` does NOT match ``leads:read``.
    # Exact match | global "*" | hierarchical prefix: ``lead:*`` grants ``lead:read``.
    if granted == required or granted == "*":
        return True
    return granted.endswith(":*") and required.startswith(granted[:-1])


def permission_granted(granted: list[str], required: str) -> bool:
    """Platform-wide granted-side matcher — route all permission checks here, not per-service re-implementations."""
    return any(_grant_matches(g, required) for g in granted)


class AuthContext(BaseModel):
    """Auth context from gateway headers + CRM lookup. Mirrors custom_claims.sql JWT hook. Frozen."""

    model_config = ConfigDict(frozen=True)

    external_auth_id: UUID = Field(
        ..., description="JWT sub claim / Supabase Auth UUID"
    )
    user_id: UUID = Field(..., description="Internal user ID")
    email: str
    first_name: str | None = None
    last_name: str | None = None
    tenant_id: UUID
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    is_active: bool = True
    is_suspended: bool = False

    correlation_id: str | None = None
    auth_provider: str = "supabase"

    @field_validator("roles", "permissions", mode="before")
    @classmethod
    def ensure_list(cls, v: Any) -> list:
        return v if isinstance(v, list) else []

    def has_permission(self, permission: str) -> bool:
        """Single platform-wide matcher — delegates to permission_granted (wildcard-aware)."""
        return permission_granted(self.permissions, permission)

    def has_any_role(self, roles: list[str]) -> bool:
        """Exact membership: True if any of ``roles`` is DIRECTLY held.

        The ONLY role check on AuthContext, deliberately. There was also a
        ``has_role`` that widened via a ``role_hierarchy`` field — it returned
        True for a role merely reached through the ``parent_role_id`` chain.
        Every one of its callers was a cross-tenant scope gate, the exact place
        inheritance must not apply, so it could only ever loosen a boundary it
        was never meant to touch. Both it and the field were removed in v0.16.0.

        Role names gate tenant scope only; feature access is permission-based
        (``has_permission`` / ``require_permission``).
        """
        return any(role in self.roles for role in roles)


class GatewayIdentityHeaders(BaseModel):
    user_id: UUID | None = None
    user_role: str | None = None
    tenant_id: UUID | None = None
    site_id: UUID | None = None
    user_email: str | None = None
    permissions: list[str] = Field(default_factory=list)
    auth_provider: str | None = None
    correlation_id: str | None = None
    gateway_signature: str | None = None
    gateway_timestamp: str | None = None
