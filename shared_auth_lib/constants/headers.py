"""Canonical gateway↔downstream header names — the single source of truth.

The gateway signs requests and downstream services verify them; both sides must
spell these header names identically or HMAC verification fails. Define them once
here so a rename can never drift between signer and verifier.
"""

from enum import StrEnum
from typing import Final


class SignedHeader(StrEnum):
    """Identity headers included in the gateway HMAC signature canonical input.

    Definition ORDER is part of the contract: signer and verifier iterate this
    sequence identically to build the same canonical string. Do not reorder.
    """

    USER_ID = "X-User-ID"
    USER_ROLE = "X-User-Role"
    TENANT_ID = "X-Tenant-ID"
    CORRELATION_ID = "X-Correlation-ID"


# Ordered list consumed by compute_signature() / verify_signature().
SIGNED_HEADERS: Final[list[str]] = [h.value for h in SignedHeader]

# Service-to-service auth header for /internal/* endpoints (bypasses HMAC).
SERVICE_TOKEN_HEADER: Final[str] = "X-Service-Token"
