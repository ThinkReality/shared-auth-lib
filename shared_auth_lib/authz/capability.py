"""The single authorization entry point.

`can()` is the only authz primitive services should call (besides AuthContext's
has_* methods). Today it delegates to flat-permission membership; `resource` is
accepted and ignored. When node-centric RBAC (doc 5) replaces the flat model,
ONLY this function's body changes — services that route every decision through
can()/require_capability need zero edits. The (ctx, permission, resource)
signature is FROZEN.
"""

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Depends
from tr_shared.exceptions import AuthorizationError

from shared_auth_lib.dependencies.auth_dependencies import require_auth
from shared_auth_lib.models.auth_context import AuthContext


def can(ctx: AuthContext, permission: str, resource: Any = None) -> bool:
    """Return whether ``ctx`` may perform ``permission``.

    Today: flat permission check. ``resource`` is the future node-scope seam and
    is intentionally unused now.
    """
    return ctx.has_permission(permission)


def require_capability(
    permission: str,
) -> Callable[..., Awaitable[AuthContext]]:
    """Dependency factory: require a capability, routed through ``can()``.

    Raises ``tr_shared.exceptions.AuthorizationError`` (403) on deny, so the
    GlobalErrorHandler renders the standard structured error body.
    """

    async def _checker(
        auth_context: AuthContext = Depends(require_auth),
    ) -> AuthContext:
        if not can(auth_context, permission):
            raise AuthorizationError(detail=f"Capability required: {permission}")
        return auth_context

    return _checker
