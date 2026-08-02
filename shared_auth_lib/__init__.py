"""shared_auth_lib — shared authorization library.

``__version__`` is single-sourced from the installed package metadata (i.e.
pyproject ``[project].version``) so the two can never drift.
"""

from importlib.metadata import version

from shared_auth_lib.authz import (
    can,
    permission_granted,
    require_capability,
)
from shared_auth_lib.constants import (
    SYSTEM_ROLES,
    SystemRole,
)
from shared_auth_lib.dependencies.auth_dependencies import (
    get_current_auth_context,
    get_current_user,
    get_auth_context_client,
    init_auth_context_client,
    reset_auth_context_client,
    optional_auth,
    require_any_role,
    require_auth,
    require_permission,
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
from shared_auth_lib.services.auth_context_client import (
    AuthContextClient,
)
from shared_auth_lib.middleware.standard_stack import (
    Slot,
    install_standard_middleware,
)
from shared_auth_lib.openapi import openapi_security_from_skip_paths
from shared_auth_lib.services.hmac_verifier import (
    compute_signature,
    verify_signature,
)

__version__ = version("shared-auth-lib")

__all__ = [
    "SYSTEM_ROLES",
    "Slot",
    "SystemRole",
    "AuthContext",
    "AuthContextClient",
    "GatewayHMACMiddleware",
    "GatewayIdentityHeaders",
    "IdentityExtractionMiddleware",
    "can",
    "compute_signature",
    "permission_granted",
    "get_current_auth_context",
    "get_current_user",
    "get_gateway_identity",
    "get_auth_context_client",
    "init_auth_context_client",
    "reset_auth_context_client",
    "optional_auth",
    "require_any_role",
    "require_auth",
    "require_capability",
    "install_standard_middleware",
    "openapi_security_from_skip_paths",
    "require_permission",
    "verify_signature",
]
