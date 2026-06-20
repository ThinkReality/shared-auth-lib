"""Shared auth constants: canonical platform roles, role groups, header names."""

from shared_auth_lib.constants.headers import (
    SERVICE_TOKEN_HEADER,
    SIGNED_HEADERS,
    SignedHeader,
)
from shared_auth_lib.constants.roles import (
    ADMIN_ROLES,
    AGENT_ROLES,
    ROLE_RANK,
    PlatformRole,
)

__all__ = [
    "ADMIN_ROLES",
    "AGENT_ROLES",
    "ROLE_RANK",
    "PlatformRole",
    "SERVICE_TOKEN_HEADER",
    "SIGNED_HEADERS",
    "SignedHeader",
]
