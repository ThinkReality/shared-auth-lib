"""Build fake ASGI headers for dev mode bypass.

When DEV_MODE_BYPASS is active, GatewayHMACMiddleware injects these
headers into the request scope so that IdentityExtractionMiddleware
(which runs next) picks them up as if the gateway had set them.

Per-request overrides via X-Dev-* headers let developers switch
personas without restarting the service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shared_auth_lib.config import AuthLibSettings


def build_dev_headers(
    existing_headers: list[tuple[bytes, bytes]],
    settings: "AuthLibSettings",
) -> list[tuple[bytes, bytes]]:
    """Return a new header list with dev identity headers appended.

    If the incoming request already carries X-Dev-* override headers,
    those take precedence over the env-var defaults. This lets developers
    test different roles/permissions per-request without restarting.
    """
    incoming = {k.lower(): v for k, v in existing_headers}

    def _pick(override_header: bytes, default: str) -> str:
        """Use the request-level override if present, else the env default."""
        val = incoming.get(override_header)
        if val:
            return val.decode("latin-1")
        return default

    user_id = _pick(b"x-dev-user-id", str(settings.DEV_USER_ID))
    tenant_id = _pick(b"x-dev-tenant-id", str(settings.DEV_TENANT_ID))
    roles = _pick(b"x-dev-roles", ",".join(settings.DEV_ROLES))
    # Take first role as the primary role header
    primary_role = roles.split(",")[0].strip()

    injected = [
        (b"x-user-id", user_id.encode()),
        (b"x-tenant-id", tenant_id.encode()),
        (b"x-user-role", primary_role.encode()),
        (b"x-auth-provider", b"dev"),
    ]

    # Keep all original headers, then append the injected ones.
    # Duplicates are fine — IdentityExtractionMiddleware reads the first
    # match via request.headers.get(), and our appended values will be
    # found because Starlette iterates headers in order and we place
    # injected ones at the END. However, to be safe, strip any
    # conflicting originals so there's no ambiguity.
    override_keys = {k for k, _ in injected}
    cleaned = [(k, v) for k, v in existing_headers if k.lower() not in override_keys]
    return cleaned + injected
