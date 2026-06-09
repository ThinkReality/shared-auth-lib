"""Authorization seam: the single can()/require_capability entry point."""

from shared_auth_lib.authz.capability import can, require_capability

__all__ = ["can", "require_capability"]
