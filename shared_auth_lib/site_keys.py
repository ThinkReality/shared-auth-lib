"""Site-key generation and hashing — the SSOT for both ends of the credential.

tr-crm-core's admin module ISSUES keys; tr-api-gateway VERIFIES them. Both import
from here so the two can never drift: a mismatch would not raise, it would simply
make every key fail to resolve.

Why SHA-256 and not bcrypt/argon2: the key is 256 bits of `secrets.token_urlsafe`
entropy, so there is no brute-force margin to defend. Password KDFs are salted by
design, which makes them non-indexable — and the gateway's whole lookup is
"find the row for this hash". This is the GitHub-PAT / Stripe model.
"""

import hashlib
import secrets
from enum import StrEnum
from typing import Final

SITE_KEY_PREFIX: Final[str] = "sk_live_"
_ENTROPY_BYTES: Final[int] = 32
_DISPLAY_PREFIX_LEN: Final[int] = 20


class SiteStatus(StrEnum):
    """Lifecycle of a registered site. Issued by tr-crm-core, enforced by tr-api-gateway.

    Two members only. There is deliberately no PENDING_VERIFICATION: domain ownership
    is not verified (D9) — the key is the credential, and a wrong primary_domain can
    only produce wrong canonical URLs for the tenant that typed it, never access to
    another tenant's data.

    Lives beside ``hash_site_key`` for the same reason that function does, and the
    reason is in this module's own docstring: a producer/verifier pair holding two
    private copies of one vocabulary drifts silently. It did. The gateway typed the
    field ``str`` and re-declared a private ``_SITE_STATUS_ACTIVE = "active"``, so a
    third member added on the issuing side alone would have made the gateway deny
    every such site with **the wrong reason** — 403 "This site is suspended" for a
    site that is not suspended — with nothing failing in either repo (A12).
    """

    ACTIVE = "active"
    SUSPENDED = "suspended"


def generate_site_key() -> tuple[str, str, str]:
    """Return ``(plaintext, sha256_hex, display_prefix)``.

    The plaintext is returned to the caller exactly once and is never stored.
    Only the hash is persisted; the display prefix exists so the UI can show a
    recognisable stub next to a key it cannot read back.
    """
    plaintext = SITE_KEY_PREFIX + secrets.token_urlsafe(_ENTROPY_BYTES)
    return plaintext, hash_site_key(plaintext), plaintext[:_DISPLAY_PREFIX_LEN]


def hash_site_key(plaintext: str) -> str:
    """SHA-256 hex digest of a site key. Lookups are always by this, never by the key."""
    if not plaintext or not plaintext.strip():
        raise ValueError("Site key must not be empty")
    return hashlib.sha256(plaintext.encode()).hexdigest()
