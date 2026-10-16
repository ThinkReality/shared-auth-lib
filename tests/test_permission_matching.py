"""Hierarchical wildcard permission matching: AuthContext.has_permission, can(), require_permission."""

from uuid import uuid4

from shared_auth_lib.authz.capability import can
from shared_auth_lib.models.auth_context import AuthContext, permission_granted


def _ctx(perms: list[str]) -> AuthContext:
    return AuthContext(
        external_auth_id=uuid4(),
        user_id=uuid4(),
        email="u@x.com",
        tenant_id=uuid4(),
        permissions=perms,
    )


def test_exact_match():
    assert permission_granted(["lead:read"], "lead:read")


def test_global_wildcard():
    assert permission_granted(["*"], "anything:here")


def test_feature_wildcard_grants_action():
    assert permission_granted(["lead:*"], "lead:read")


def test_multi_segment_granted_by_feature_wildcard():
    assert permission_granted(["a:*"], "a:b:c")


def test_multi_segment_granted_by_mid_wildcard():
    assert permission_granted(["a:b:*"], "a:b:c")


def test_feature_wildcard_does_not_leak_to_sibling_prefix():
    assert not permission_granted(["lead:*"], "leads:read")


def test_mid_wildcard_does_not_grant_other_branch():
    assert not permission_granted(["a:b:*"], "a:c:d")


def test_exact_grant_does_not_imply_wildcard():
    assert not permission_granted(["lead:read"], "lead:*")


def test_can_inherits_wildcard():
    assert can(_ctx(["lead:*"]), "lead:update")


def test_deny_when_absent():
    assert not permission_granted(["lead:read"], "listing:read")


def test_permission_granted_matches_has_permission():
    """The public seam is the exact same matcher services must route through."""
    cases = [
        (["lead:read"], "lead:read", True),
        (["*"], "lead:read", True),
        (["lead:*"], "lead:read", True),
        (["finance:invoices:*"], "finance:invoices:read", True),
        (["listing:*"], "lead:read", False),
        (["lead:read"], "listing:read", False),
        ([], "lead:read", False),
    ]
    for granted, required, expected in cases:
        assert permission_granted(granted, required) is expected
        assert _ctx(granted).has_permission(required) is expected
