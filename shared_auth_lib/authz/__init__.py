"""Authorization seam: the single can()/require_capability entry point."""

from shared_auth_lib.authz.capability import can, require_capability
from shared_auth_lib.models.auth_context import permission_granted

__all__ = ["can", "permission_granted", "require_capability"]
