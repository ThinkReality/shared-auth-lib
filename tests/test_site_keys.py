"""hash_site_key is the SSOT shared by the issuer (crm-core) and the verifier
(gateway). If they ever hash differently, every key silently stops resolving."""

import hashlib
import json

import pytest
from shared_auth_lib.site_keys import (
    SITE_KEY_PREFIX,
    SiteStatus,
    generate_site_key,
    hash_site_key,
)


def test_generated_key_has_live_prefix():
    plaintext, _, _ = generate_site_key()
    assert plaintext.startswith(SITE_KEY_PREFIX)


def test_generated_keys_are_unique():
    keys = {generate_site_key()[0] for _ in range(100)}
    assert len(keys) == 100


def test_hash_is_sha256_hex():
    plaintext, key_hash, _ = generate_site_key()
    assert key_hash == hashlib.sha256(plaintext.encode()).hexdigest()
    assert len(key_hash) == 64
    assert all(c in "0123456789abcdef" for c in key_hash)


def test_hash_is_deterministic():
    assert hash_site_key("sk_live_abc") == hash_site_key("sk_live_abc")


def test_display_prefix_is_first_twenty_chars():
    plaintext, _, prefix = generate_site_key()
    assert prefix == plaintext[:20]
    assert len(prefix) == 20


def test_display_prefix_does_not_reveal_the_key():
    """20 chars = the 8-char literal prefix + 12 chars of a 43-char body. The
    remaining entropy must stay far beyond brute force."""
    plaintext, _, prefix = generate_site_key()
    assert len(plaintext) - len(prefix) > 24


@pytest.mark.parametrize("bad", ["", "   "])
def test_hash_rejects_empty(bad):
    with pytest.raises(ValueError):
        hash_site_key(bad)


class TestSiteStatus:
    """The other half of the same producer/verifier contract (A12).

    The wire values are asserted explicitly, not derived from the members: they are
    persisted in `admin_panel_tenant_sites.status` (a `String(30)` with
    `server_default 'active'`) and compared by the gateway. Renaming a member without
    changing its value must stay possible; changing a *value* must break here.
    """

    def test_members_and_wire_values_are_exactly_these(self):
        assert {s.name: s.value for s in SiteStatus} == {
            "ACTIVE": "active",
            "SUSPENDED": "suspended",
        }

    def test_is_a_str_enum_so_it_serialises_as_its_value(self):
        assert SiteStatus.ACTIVE == "active"
        assert json.dumps({"status": SiteStatus.ACTIVE}) == '{"status": "active"}'

    def test_unknown_status_is_rejected(self):
        """Gateway boundary behaviour (A12, Option A): a status this library does not
        know raises rather than being silently treated as not-active, which would deny
        the request with the wrong reason."""
        with pytest.raises(ValueError):
            SiteStatus("archived")
