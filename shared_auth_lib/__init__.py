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
from shared_auth_lib.services.auth_context_client import (
    AuthContextClient,
)
from shared_auth_lib.services.hmac_verifier import (
    compute_signature,
    verify_signature,
)

__version__ = "0.12.0"

__all__ = [
    "SYSTEM_ROLES",
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
    "init_auth_context_client",
    "optional_auth",
    "require_any_role",
    "require_auth",
    "require_capability",
    "require_permission",
    "require_role",
    "verify_signature",
]
