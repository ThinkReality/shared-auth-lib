"""Build a fake GatewayIdentityHeaders for DEV_MODE_BYPASS.

When the bypass is active, GatewayHMACMiddleware sets
`request.state.identity` directly (not via ASGI header mutation —
Starlette's BaseHTTPMiddleware doesn't reliably propagate header
changes across middleware boundaries).

Per-request overrides via X-Dev-* headers let developers switch
personas without restarting the container.
"""

from __future__ import annotations

from uuid import UUID
from typing import TYPE_CHECKING

from starlette.requests import Request

from shared_auth_lib.config import get_settings
from shared_auth_lib.models.auth_context import GatewayIdentityHeaders

if TYPE_CHECKING:
    from shared_auth_lib.config import AuthLibSettings


def build_dev_identity(request: Request) -> GatewayIdentityHeaders:
    """Return a fake admin identity, honouring X-Dev-* override headers."""
    settings: AuthLibSettings = get_settings()
    headers = request.headers

    user_id = _parse_uuid(headers.get("x-dev-user-id")) or settings.DEV_USER_ID
    tenant_id = (
        _parse_uuid(headers.get("x-dev-tenant-id")) or settings.DEV_TENANT_ID
    )
    roles_hdr = headers.get("x-dev-roles")
    primary_role = (
        roles_hdr.split(",")[0].strip()
        if roles_hdr
        else (settings.DEV_ROLES[0] if settings.DEV_ROLES else "ADMIN")
    )

    return GatewayIdentityHeaders(
        user_id=user_id,
        tenant_id=tenant_id,
        user_role=primary_role,
        auth_provider="dev",
        correlation_id=headers.get("x-correlation-id"),
    )


def _parse_uuid(value: str | None) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None
