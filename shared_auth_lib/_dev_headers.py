"""Build a canned AuthContext for DEV_MODE_BYPASS.

Starlette's BaseHTTPMiddleware doesn't reliably propagate scope or
request.state mutations across middleware boundaries. Instead of
injecting identity upstream, the bypass is applied inside the
`require_auth` FastAPI dependency by calling
`build_dev_auth_context(request)` — this is the single source of
truth for the fake dev persona.

Per-request overrides via X-Dev-* headers let developers switch
personas without restarting the container.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from shared_auth_lib.config import get_settings
from shared_auth_lib.models.auth_context import AuthContext

if TYPE_CHECKING:
    from starlette.requests import Request


def build_dev_auth_context(
    request: "Request | None" = None,
    correlation_id: str | None = None,
) -> AuthContext:
    """Return a dev AuthContext, honouring X-Dev-* headers when a Request is given.

    Precedence (highest to lowest):
      1. X-Dev-* request headers (per-request override)
      2. AUTH_LIB_DEV_* env vars (container-wide default)
      3. Hardcoded fallbacks (admin + wildcard permissions)

    Parameters:
        request: The incoming request, for per-request overrides. Optional
            so callers outside the FastAPI dependency chain (e.g.
            AuthContextClient) can still use the helper with env defaults.
        correlation_id: Explicit correlation ID. If None, falls back to
            X-Correlation-Id on the request.
    """
    settings = get_settings()

    user_id = (
        _parse_uuid(_hget(request, "x-dev-user-id"))
        or settings.DEV_USER_ID
    )
    tenant_id = (
        _parse_uuid(_hget(request, "x-dev-tenant-id"))
        or settings.DEV_TENANT_ID
    )
    roles = _parse_csv(_hget(request, "x-dev-roles")) or list(settings.DEV_ROLES)
    permissions = (
        _parse_csv(_hget(request, "x-dev-permissions"))
        or list(settings.DEV_PERMISSIONS)
    )
    email = _hget(request, "x-dev-email") or settings.DEV_EMAIL
    first_name = _hget(request, "x-dev-first-name") or "Dev"
    last_name = _hget(request, "x-dev-last-name") or "User"
    resolved_correlation = correlation_id or _hget(request, "x-correlation-id")

    return AuthContext(
        external_auth_id=user_id,
        user_id=user_id,
        tenant_id=tenant_id,
        email=email,
        first_name=first_name,
        last_name=last_name,
        roles=roles,
        permissions=permissions,
        role_hierarchy=[],
        is_active=True,
        is_suspended=False,
        auth_provider="dev",
        correlation_id=resolved_correlation,
    )


def _hget(request: "Request | None", key: str) -> str | None:
    """Case-insensitive header lookup, tolerant of missing request."""
    if request is None:
        return None
    return request.headers.get(key)


def _parse_uuid(value: str | None) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def _parse_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    parts = [item.strip() for item in value.split(",") if item.strip()]
    return parts or None
