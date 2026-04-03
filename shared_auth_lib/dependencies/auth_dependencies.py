"""FastAPI dependencies for authentication and authorization enforcement.

Provides Depends()-compatible functions for route handlers:
- require_auth: Requires authenticated user with active account.
- require_permission: Requires a specific permission string.
- require_role: Requires a specific role (includes hierarchy).
- require_any_role: Requires any of a list of roles.
- optional_auth: Returns AuthContext or None (no 401).
"""

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, status

from shared_auth_lib.exceptions import AuthContextNotFoundError
from shared_auth_lib.logging import get_logger
from shared_auth_lib.middleware.identity_middleware import (
    get_gateway_identity,
)
from shared_auth_lib.models.auth_context import (
    AuthContext,
    GatewayIdentityHeaders,
)
from shared_auth_lib.services.auth_context_client import (
    AuthContextClient,
)

logger = get_logger(__name__)

# Dedicated audit logger for security monitoring dashboards.
# Emits structured events that can be consumed by Grafana/Loki
# alerting rules (e.g., "50+ auth failures from same IP in 5 min").
_audit_logger = get_logger("shared_auth_lib.audit")


class _AuthClientRegistry:
    """Thread-safe class-level registry for the AuthContextClient singleton.

    Using a class variable instead of a bare module global avoids the
    ``global`` keyword, enables proper test isolation via ``reset()``,
    and prevents accidental sharing across unrelated app instances.
    """

    _client: AuthContextClient | None = None

    @classmethod
    def set(cls, client: AuthContextClient) -> None:
        cls._client = client

    @classmethod
    def get(cls) -> AuthContextClient:
        if cls._client is None:
            raise RuntimeError(
                "AuthContextClient not initialized. "
                "Call init_auth_context_client() during app startup."
            )
        return cls._client

    @classmethod
    def reset(cls) -> None:
        """Reset the registry — use only in tests."""
        cls._client = None


def init_auth_context_client(
    client: AuthContextClient,
) -> None:
    """Initialize the AuthContextClient for this process.

    Call this once during application startup (lifespan).
    """
    _AuthClientRegistry.set(client)


def get_auth_context_client() -> AuthContextClient:
    """Return the initialized AuthContextClient.

    Raises RuntimeError if init_auth_context_client() was not called.
    """
    return _AuthClientRegistry.get()


async def require_auth(
    request: Request,
    identity: GatewayIdentityHeaders = Depends(
        get_gateway_identity
    ),
    client: AuthContextClient = Depends(
        get_auth_context_client
    ),
) -> AuthContext:
    """Require an authenticated, active, non-suspended user.

    Usage::

        @router.get("/protected")
        async def protected(
            auth: AuthContext = Depends(require_auth),
        ):
            ...
    """
    # Extract source IP for audit trail
    _source_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or (request.client.host if request.client else "unknown")
    )

    if not identity.user_id:
        _audit_logger.warning(
            "auth_failure",
            extra={
                "audit_event": "auth_failure",
                "reason": "missing_user_id",
                "source_ip": _source_ip,
                "path": request.url.path,
                "correlation_id": identity.correlation_id,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        auth_context = await client.get_auth_context(
            identity.user_id,
            correlation_id=identity.correlation_id,
        )
    except AuthContextNotFoundError:
        _audit_logger.warning(
            "auth_failure",
            extra={
                "audit_event": "auth_failure",
                "reason": "context_not_found",
                "external_auth_id": str(identity.user_id),
                "source_ip": _source_ip,
                "path": request.url.path,
                "correlation_id": identity.correlation_id,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication",
        )

    if not auth_context.is_active:
        _audit_logger.warning(
            "auth_failure",
            extra={
                "audit_event": "auth_failure",
                "reason": "inactive_account",
                "user_id": str(auth_context.user_id),
                "tenant_id": str(auth_context.tenant_id),
                "source_ip": _source_ip,
                "path": request.url.path,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
        )

    if auth_context.is_suspended:
        _audit_logger.warning(
            "auth_failure",
            extra={
                "audit_event": "auth_failure",
                "reason": "suspended_account",
                "user_id": str(auth_context.user_id),
                "tenant_id": str(auth_context.tenant_id),
                "source_ip": _source_ip,
                "path": request.url.path,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is suspended",
        )

    auth_context = auth_context.model_copy(
        update={"correlation_id": identity.correlation_id}
    )
    request.state.auth_context = auth_context
    return auth_context


def require_permission(
    permission: str,
) -> Callable[..., Awaitable[AuthContext]]:
    """Dependency factory: require a specific permission.

    Usage::

        @router.delete("/users/{id}")
        async def delete_user(
            auth: AuthContext = Depends(
                require_permission("user:delete")
            ),
        ):
            ...
    """

    async def _checker(
        auth_context: AuthContext = Depends(require_auth),
    ) -> AuthContext:
        if not auth_context.has_permission(permission):
            _audit_logger.warning(
                "auth_failure",
                extra={
                    "audit_event": "auth_failure",
                    "reason": "permission_denied",
                    "user_id": str(auth_context.user_id),
                    "tenant_id": str(auth_context.tenant_id),
                    "required_permission": permission,
                    "permissions_count": len(
                        auth_context.permissions
                    ),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}",
            )
        return auth_context

    return _checker


def require_role(
    role: str,
) -> Callable[..., Awaitable[AuthContext]]:
    """Dependency factory: require a specific role (or higher via hierarchy).

    Usage::

        @router.get("/admin/users")
        async def list_users(
            auth: AuthContext = Depends(require_role("ADMIN")),
        ):
            ...
    """

    async def _checker(
        auth_context: AuthContext = Depends(require_auth),
    ) -> AuthContext:
        if not auth_context.has_role(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {role}",
            )
        return auth_context

    return _checker


def require_any_role(
    roles: list[str],
) -> Callable[..., Awaitable[AuthContext]]:
    """Dependency factory: require any of the specified roles.

    Usage::

        @router.post("/leads/export")
        async def export(
            auth: AuthContext = Depends(
                require_any_role(["ADMIN", "MANAGER"])
            ),
        ):
            ...
    """

    async def _checker(
        auth_context: AuthContext = Depends(require_auth),
    ) -> AuthContext:
        if not auth_context.has_any_role(roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"One of roles required: "
                    f"{', '.join(roles)}"
                ),
            )
        return auth_context

    return _checker


async def optional_auth(
    identity: GatewayIdentityHeaders = Depends(
        get_gateway_identity
    ),
    client: AuthContextClient = Depends(
        get_auth_context_client
    ),
) -> AuthContext | None:
    """Optional authentication dependency.

    Returns AuthContext if the user is authenticated, None otherwise.
    Does not raise 401 for unauthenticated requests.

    Usage::

        @router.get("/listings/featured")
        async def featured(
            auth: AuthContext | None = Depends(optional_auth),
        ):
            ...
    """
    if not identity.user_id:
        return None

    try:
        return await client.get_auth_context(
            identity.user_id,
            correlation_id=identity.correlation_id,
        )
    except AuthContextNotFoundError:
        return None


async def get_current_user(
    auth_context: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    """Standard get_current_user bridge for downstream services.

    Converts AuthContext into the dict format that route handlers expect.
    Provides consistent field names across all services.

    Returns:
        dict with keys: id, sub, email, tenant_id, role, roles, permissions
    """
    return {
        "id": str(auth_context.user_id),
        "sub": str(auth_context.external_auth_id),
        "email": auth_context.email,
        "tenant_id": str(auth_context.tenant_id),
        "role": auth_context.roles[0] if auth_context.roles else "N/A",
        "roles": auth_context.roles,
        "permissions": auth_context.permissions,
    }


def get_current_auth_context(
    request: Request,
) -> AuthContext | None:
    """Retrieve AuthContext from request.state (set by require_auth)."""
    return getattr(request.state, "auth_context", None)
