"""HMAC signature computation and verification for gateway-signed requests.

Security notes:
- Replay protection uses a timestamp tolerance window (default 30 seconds).
  An attacker who captures a valid signed request has at most 30 seconds to
  replay it. This is an accepted risk for internal-network traffic between
  API gateway and downstream services. For highly sensitive operations
  (financial transactions), add Redis-based nonce deduplication on top.
- Query parameters are NOT included in the HMAC signature. This is an
  accepted risk since query params control pagination/filtering, not
  authorization. Tenant isolation is enforced by BaseRepository using
  auth_context.tenant_id from CRM-backend.
"""

import hashlib
import hmac
from datetime import UTC, datetime
from typing import Final

TIMESTAMP_TOLERANCE_SECONDS: Final[int] = 30
SIGNED_HEADERS: Final[list[str]] = [
    "X-User-ID",
    "X-User-Role",
    "X-Tenant-ID",
    "X-Correlation-ID",
]


def _get_header_value(
    headers: dict[str, str], name: str
) -> str:
    """Case-insensitive header lookup.

    The gateway sets headers with mixed case (e.g. X-User-ID), but
    Starlette normalises incoming headers to lowercase. This helper
    ensures both signer and verifier resolve the same value regardless
    of casing in the dict keys.
    """
    value = headers.get(name)
    if value is not None:
        return value
    lower_name = name.lower()
    for key, val in headers.items():
        if key.lower() == lower_name:
            return val
    return ""


def build_canonical_string(
    method: str,
    path: str,
    headers: dict[str, str],
    timestamp: str,
) -> str:
    """Build canonical string for HMAC signing.

    Format: METHOD\\nPATH\\nHEADER_VALUES...\\nTIMESTAMP

    The canonical string is deterministic given the same inputs,
    ensuring both gateway (signer) and service (verifier) produce
    identical signatures.
    """
    # Normalize: strip trailing slash so /api/v1/leads and /api/v1/leads/
    # produce identical signatures. FastAPI services may redirect between
    # the two forms (307), and httpx follow_redirects changes the path
    # the downstream verifier sees.
    normalized_path = path.rstrip("/") or "/"

    components = [
        method.upper(),
        normalized_path,
    ]
    for header_name in SIGNED_HEADERS:
        components.append(
            _get_header_value(headers, header_name)
        )
    components.append(timestamp)
    return "\n".join(components)


def compute_signature(
    method: str,
    path: str,
    headers: dict[str, str],
    secret: str,
    timestamp: str,
) -> str:
    """Compute HMAC-SHA256 signature for a gateway request.

    Used by the API Gateway to sign outgoing requests. Downstream
    services call verify_signature() with the same shared secret
    to validate authenticity.

    Returns:
        Hex-encoded HMAC-SHA256 signature.
    """
    canonical = build_canonical_string(
        method, path, headers, timestamp
    )
    return hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_signature(
    method: str,
    path: str,
    headers: dict[str, str],
    secret: str,
    signature: str,
    timestamp: str,
    tolerance_seconds: int = TIMESTAMP_TOLERANCE_SECONDS,
) -> bool:
    """Verify HMAC signature from gateway.

    Performs two checks:
    1. Timestamp freshness (within tolerance window) to prevent
       replay attacks.
    2. Constant-time signature comparison to prevent timing attacks.

    Returns:
        True if signature is valid and timestamp is within tolerance.
    """
    try:
        ts = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
        now = datetime.now(UTC)
        if abs((now - ts).total_seconds()) > tolerance_seconds:
            return False
    except (ValueError, TypeError, AttributeError):
        return False

    expected = compute_signature(
        method, path, headers, secret, timestamp
    )
    return hmac.compare_digest(expected, signature)
