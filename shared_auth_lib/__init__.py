"""Shared authorization library for ThinkRealty microservices.

Public API re-exports for convenient downstream usage::

    from shared_auth_lib import (
        AuthContext,
        GatewayIdentityHeaders,
        GatewayHMACMiddleware,
        IdentityExtractionMiddleware,
        AuthContextClient,
        require_auth,
        require_permission,
        require_role,
        require_any_role,
        optional_auth,
        get_current_user,
        init_auth_context_client,
        compute_signature,
        verify_signature,
    )
"""

from shared_auth_lib.authz import (
    can,
    require_capability,
)
from shared_auth_lib.constants import (
    ADMIN_ROLES,
    AGENT_ROLES,
    ROLE_RANK,
    PlatformRole,
)
from shared_auth_lib.dependencies.auth_dependencies import (
    get_current_auth_context,
    get_current_user,
    init_auth_context_client,
    optional_auth,
    require_any_role,
    require_auth,
    require_permission,
    require_role,
)
from shared_auth_lib.middleware.hmac_middleware import (
    GatewayHMACMiddleware,
)
from shared_auth_lib.middleware.identity_middleware import (
    IdentityExtractionMiddleware,
    get_gateway_identity,
)
from shared_auth_lib.models.auth_context import (
    AuthContext,
    GatewayIdentityHeaders,
)
from shared_auth_lib.permissions import (
    ATTENDANCE_APPROVE,
    ATTENDANCE_EXCEPTIONS_MANAGE,
    ATTENDANCE_EXPORT,
    ATTENDANCE_MANUAL_CREATE,
    ATTENDANCE_READ,
    ATTENDANCE_SYNC,
    EMPLOYEES_READ,
    EMPLOYEES_SYNC,
    HIKCENTRAL_READ,
)
from shared_auth_lib.services.auth_context_client import (
    AuthContextClient,
)
from shared_auth_lib.services.hmac_verifier import (
    compute_signature,
    verify_signature,
)

__all__ = [
    "ADMIN_ROLES",
    "AGENT_ROLES",
    "AuthContext",
    "AuthContextClient",
    "PlatformRole",
    "ROLE_RANK",
    "ATTENDANCE_APPROVE",
    "ATTENDANCE_EXCEPTIONS_MANAGE",
    "ATTENDANCE_EXPORT",
    "ATTENDANCE_MANUAL_CREATE",
    "ATTENDANCE_READ",
    "ATTENDANCE_SYNC",
    "EMPLOYEES_READ",
    "EMPLOYEES_SYNC",
    "HIKCENTRAL_READ",
    "GatewayHMACMiddleware",
    "GatewayIdentityHeaders",
    "IdentityExtractionMiddleware",
    "can",
    "compute_signature",
    "get_current_auth_context",
    "get_current_user",
    "get_gateway_identity",
    "init_auth_context_client",
    "optional_auth",
    "require_any_role",
    "require_auth",
    "require_capability",
    "require_permission",
    "require_role",
    "verify_signature",
]
