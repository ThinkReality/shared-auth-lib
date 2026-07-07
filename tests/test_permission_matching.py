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
    assert _ctx(["lead:read"]).has_permission("lead:read")


def test_global_wildcard():
    assert _ctx(["*"]).has_permission("anything:here")


def test_feature_wildcard_grants_action():
    assert _ctx(["lead:*"]).has_permission("lead:read")


def test_multi_segment_granted_by_feature_wildcard():
    assert _ctx(["a:*"]).has_permission("a:b:c")


def test_multi_segment_granted_by_mid_wildcard():
    assert _ctx(["a:b:*"]).has_permission("a:b:c")


def test_feature_wildcard_does_not_leak_to_sibling_prefix():
    assert not _ctx(["lead:*"]).has_permission("leads:read")


def test_mid_wildcard_does_not_grant_other_branch():
    assert not _ctx(["a:b:*"]).has_permission("a:c:d")


def test_exact_grant_does_not_imply_wildcard():
    assert not _ctx(["lead:read"]).has_permission("lead:*")


def test_can_inherits_wildcard():
    assert can(_ctx(["lead:*"]), "lead:edit")


def test_deny_when_absent():
    assert not _ctx(["lead:read"]).has_permission("listing:read")


def test_permission_granted_matches_has_permission():
    """The public seam is the exact same matcher services must route through."""
    cases = [
        (["lead:read"], "lead:read", True),
        (["*"], "anything:here", True),
        (["lead:*"], "lead:read", True),
        (["a:b:*"], "a:b:c", True),
        (["lead:*"], "leads:read", False),
        (["lead:read"], "lead:*", False),
        (["lead:read"], "listing:read", False),
        ([], "lead:read", False),
    ]
    for granted, required, expected in cases:
        assert permission_granted(granted, required) is expected
        assert _ctx(granted).has_permission(required) is expected
