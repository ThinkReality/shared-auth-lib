"""Pydantic models for authorization context and gateway identity headers."""

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuthContext(BaseModel):
    """Authorization context extracted from gateway headers + CRM-backend lookup.

    Mirrors JWT custom claims from custom_claims.sql hook.
    Cache key uses external_auth_id (Supabase Auth UUID).

    Frozen to prevent accidental mutation after construction.
    Use ``model_copy(update={...})`` to create modified copies.
    """

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
    role_hierarchy: list[str] = Field(default_factory=list)

    correlation_id: str | None = None
    auth_provider: str = "supabase"

    @field_validator("roles", "permissions", mode="before")
    @classmethod
    def ensure_list(cls, v: Any) -> list:
        return v if isinstance(v, list) else []

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions

    def has_any_role(self, roles: list[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role (includes hierarchy)."""
        return role in self.roles or role in self.role_hierarchy


class GatewayIdentityHeaders(BaseModel):
    """Headers forwarded by API Gateway after JWT validation."""

    user_id: UUID | None = None
    user_role: str | None = None
    tenant_id: UUID | None = None
    user_email: str | None = None
    auth_provider: str | None = None
    correlation_id: str | None = None
    gateway_signature: str | None = None
    gateway_timestamp: str | None = None
