"""Tenant module entitlement — the predicate and its dependency factory.

Co-located exactly like ``authz/capability.py``: ``is_module_enabled`` holds the
policy and imports nothing from FastAPI, ``require_module`` holds only the
wiring. Entitlement is a distinct question from capability — capability asks
"may this user do X", entitlement asks "did this tenant buy X" — so it is a
sibling of ``can()``, not a call through it. ``can``'s
``(ctx, permission, resource)`` signature is frozen and a module check does not
fit it.
"""

from collections.abc import Awaitable, Callable

from fastapi import Depends
from tr_shared.contracts import Feature, ensure_entitlement_module
from tr_shared.exceptions import AuthorizationError

from shared_auth_lib.dependencies.auth_dependencies import require_auth
from shared_auth_lib.logging import get_logger
from shared_auth_lib.models.auth_context import AuthContext

__all__ = ["is_module_enabled", "require_module"]

# The library's structured logger, and the SAME "shared_auth_lib.audit" channel
# auth_dependencies.py:41 already uses for every deny it records. `logging.getLogger`
# here would emit unstructured records from a security guard's audit path and split
# the audit stream in two.
_audit_logger = get_logger("shared_auth_lib.audit")


def is_module_enabled(ctx: AuthContext, module: Feature) -> bool:
    """Whether this tenant holds *module*.

    Exact membership, no wildcard and no hierarchy: unlike permissions, a module
    is bought or not bought. An empty ``enabled_modules`` grants nothing — the
    column defaults to ``'{}'``, so an unseeded tenant is denied rather than
    silently entitled.
    """
    return module.value in ctx.enabled_modules


def require_module(module: Feature) -> Callable[..., Awaitable[AuthContext]]:
    """Dependency factory: require *module* on the caller's tenant.

    Raises ``ValueError`` at call time — i.e. when the router module is imported
    — if *module* is not a tenant-toggleable unit, so a typo fails the build
    rather than 403ing in production.

    The check delegates to ``tr_shared``'s ``ensure_entitlement_module`` rather
    than restating it. That sentence used to be hand-written here, in
    ``taxonomy.py`` and in crm-core's ``set_tenant_modules`` — three copies of one
    rule across three repos, drifting independently.
    """
    ensure_entitlement_module(module)

    async def _checker(
        auth_context: AuthContext = Depends(require_auth),
    ) -> AuthContext:
        if not is_module_enabled(auth_context, module):
            _audit_logger.warning(
                "module_not_entitled",
                extra={
                    "audit_event": "authz_failure",
                    "module": module.value,
                    "tenant_id": str(auth_context.tenant_id),
                    "user_id": str(auth_context.user_id),
                },
            )
            raise AuthorizationError(
                detail=f"Module not enabled for this tenant: {module.value}",
                code="AUTHLIB_AUTH_011",
            )
        return auth_context

    # NOT `_required_permissions` — route_surfaces reads that attribute to
    # classify a route as business. An entitlement gate is a different question
    # and must never stand in for a missing permission gate.
    #
    # `setattr` rather than attribute assignment + `# type: ignore`: this is the
    # house convention for the same problem two files away
    # (authz/capability.py sets `_required_permissions` exactly this way), and it
    # needs no suppression comment for mypy to accept.
    setattr(_checker, "_required_modules", (module,))
    return _checker
