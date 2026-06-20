"""Gateway↔downstream HMAC signature contract.

The canonical header NAME strings are the single source of truth in
``tr_shared.contracts.headers.HttpHeader`` (the base lib every service depends
on). This module pins the SUBSET that is HMAC-signed and, critically, their
ORDER — signer and verifier iterate this sequence identically to build the same
canonical string. Names derive from ``HttpHeader`` so a rename can never drift;
the order lives here because it is the signing contract, not a naming concern.
"""

from enum import StrEnum
from typing import Final

from tr_shared.contracts.headers import HttpHeader


class SignedHeader(StrEnum):
    """Values derive from HttpHeader (SSOT). ORDER is the signing contract — do not reorder."""

    USER_ID = HttpHeader.USER_ID.value
    USER_ROLE = HttpHeader.USER_ROLE.value
    TENANT_ID = HttpHeader.TENANT_ID.value
    CORRELATION_ID = HttpHeader.CORRELATION_ID.value


SIGNED_HEADERS: Final[list[str]] = [h.value for h in SignedHeader]

SERVICE_TOKEN_HEADER: Final[str] = HttpHeader.SERVICE_TOKEN.value
