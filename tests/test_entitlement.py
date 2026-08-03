from uuid import uuid4

import pytest
from tr_shared.contracts import Feature
from tr_shared.exceptions import AuthorizationError

from shared_auth_lib.authz.entitlement import is_module_enabled, require_module
from shared_auth_lib.models.auth_context import AuthContext


def _ctx(*modules: str) -> AuthContext:
    return AuthContext(
        external_auth_id=uuid4(),
        user_id=uuid4(),
        email="a@b.com",
        tenant_id=uuid4(),
        enabled_modules=list(modules),
    )


def test_predicate_is_true_when_the_module_is_enabled():
    assert is_module_enabled(_ctx("listing", "cms"), Feature.LISTING) is True


def test_predicate_is_false_when_the_module_is_absent():
    assert is_module_enabled(_ctx("cms"), Feature.LISTING) is False


def test_predicate_is_false_for_an_empty_entitlement():
    """Fail-closed. The DB column defaults to '{}' on purpose."""
    assert is_module_enabled(_ctx(), Feature.LISTING) is False


def test_factory_rejects_a_non_toggleable_feature_at_import_time():
    """Fails when the router module is imported, not when a request arrives."""
    with pytest.raises(ValueError, match="not a tenant-toggleable module"):
        require_module(Feature.MEDIA)


async def test_checker_returns_the_context_when_entitled():
    checker = require_module(Feature.LISTING)
    ctx = _ctx("listing")
    assert await checker(auth_context=ctx) is ctx


async def test_checker_raises_authorization_error_when_not_entitled():
    checker = require_module(Feature.LISTING)
    with pytest.raises(AuthorizationError) as exc:
        await checker(auth_context=_ctx("cms"))
    # `.error_code`, NOT `.code`. BaseAPIException stores the code it is given as
    # `self.error_code` (tr_shared/exceptions.py:23) and subclasses HTTPException,
    # which has no `.code` at all — `exc.value.code` AttributeErrors, so a test
    # written that way can never reach "all PASS".
    assert exc.value.error_code == "AUTHLIB_AUTH_011"
    assert exc.value.status_code == 403


def test_checker_marks_modules_not_permissions():
    """`route_surfaces._declares_a_gate` reads `_required_permissions` to classify
    a route as business. A module gate must never satisfy that check — it is a
    different question, and conflating them would let an entitlement gate stand in
    for a missing permission gate."""
    checker = require_module(Feature.LISTING)
    assert checker._required_modules == (Feature.LISTING,)
    assert not hasattr(checker, "_required_permissions")
