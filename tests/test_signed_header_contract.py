"""SIGNED_HEADERS order IS the HMAC wire contract.

build_canonical_string appends _get_header_value(...) for every member, and an
absent header contributes "". So adding, removing, or reordering a member changes
the canonical string of EVERY request — a gateway on one version and a service on
another produce different signatures and every route 403s.

This test exists so that change can only ever be deliberate. If it fails, you are
about to break the fleet: read plans/2026-07-25-tenant-site-registry-p1-implementation.md
Task 3 before touching it.
"""

from shared_auth_lib.constants.headers import SIGNED_HEADERS, SignedHeader
from shared_auth_lib.services.hmac_verifier import build_canonical_string

_EXPECTED_ORDER = [
    "X-User-ID",
    "X-User-Role",
    "X-Tenant-ID",
    "X-Correlation-ID",
    "X-User-Email",
    "X-User-Permissions",
    "X-Site-Id",
]


def test_signed_header_order_is_exact():
    assert SIGNED_HEADERS == _EXPECTED_ORDER


def test_signed_header_count_is_seven():
    assert len(SignedHeader) == 7


def test_canonical_string_has_one_component_per_signed_header():
    canonical = build_canonical_string(
        method="POST",
        path="/api/v1/public/leads",
        headers={},
        timestamp="2026-07-26T00:00:00+00:00",
    )
    # METHOD + PATH + one slot per signed header + TIMESTAMP
    assert len(canonical.split("\n")) == 2 + len(SIGNED_HEADERS) + 1


def test_absent_headers_become_empty_components():
    canonical = build_canonical_string(
        method="GET", path="/x", headers={}, timestamp="ts"
    )
    assert canonical == "GET\n/x\n" + "\n" * len(SIGNED_HEADERS) + "ts"


def test_site_id_is_last():
    """Appended, not inserted — keeps the diff to one trailing slot."""
    assert SIGNED_HEADERS[-1] == SignedHeader.SITE_ID.value
