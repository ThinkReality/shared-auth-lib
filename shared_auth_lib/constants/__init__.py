"""Shared auth constants: canonical platform roles, role groups, header names."""

from shared_auth_lib.constants.headers import (
    SERVICE_TOKEN_HEADER,
    SIGNED_HEADERS,
    SignedHeader,
)
from shared_auth_lib.constants.roles import (
    SYSTEM_ROLES,
    SystemRole,
)

__all__ = [
    "SYSTEM_ROLES",
    "SystemRole",
    "SERVICE_TOKEN_HEADER",
    "SIGNED_HEADERS",
    "SignedHeader",
]
