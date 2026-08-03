import pytest
from fastapi import APIRouter, Depends, FastAPI
from tr_shared.contracts import Feature

from shared_auth_lib.authz.entitlement import require_module
from shared_auth_lib.dependencies.auth_dependencies import require_auth
from shared_auth_lib.testing import ModuleExemption, assert_module_gates

_REASON = (
    "service-to-service subtree gated by validate_service_token; the caller is a "
    "service with no AuthContext and no tenant, so there is no entitlement to check"
)


def _app(*, gated: bool, with_internal: bool = False, internal_gated: bool = False):
    app = FastAPI()
    deps = [Depends(require_module(Feature.DLD))] if gated else []
    router = APIRouter(dependencies=deps)

    @router.get("/reports")
    async def _reports() -> dict:
        return {}

    app.include_router(router, prefix="/api/v1/dld")

    if with_internal:
        internal_deps = [Depends(require_auth)] if internal_gated else []
        internal = APIRouter(dependencies=internal_deps)

        @internal.post("/bulk")
        async def _bulk() -> dict:
            return {}

        app.include_router(internal, prefix="/api/v1/dld/internal")
    return app


def test_passes_when_every_route_under_the_prefix_is_gated():
    assert_module_gates(_app(gated=True), {"/api/v1/dld/": Feature.DLD})


def test_fails_when_a_route_under_the_prefix_is_ungated():
    with pytest.raises(AssertionError, match="GET /api/v1/dld/reports"):
        assert_module_gates(_app(gated=False), {"/api/v1/dld/": Feature.DLD})


def test_fails_when_the_prefix_matches_no_route():
    """A typo'd prefix would otherwise pass vacuously, proving nothing."""
    with pytest.raises(AssertionError, match="matched no route"):
        assert_module_gates(_app(gated=True), {"/api/v1/typo/": Feature.DLD})


def test_fails_when_the_gate_names_the_wrong_module():
    with pytest.raises(AssertionError, match="GET /api/v1/dld/reports"):
        assert_module_gates(_app(gated=True), {"/api/v1/dld/": Feature.CMS})


def test_an_exempt_prefix_excuses_its_unauthenticated_subtree():
    assert_module_gates(
        _app(gated=True, with_internal=True),
        {"/api/v1/dld/": Feature.DLD},
        exempt_prefixes={"/api/v1/dld/internal/": ModuleExemption(reason=_REASON)},
    )


def test_an_exempt_prefix_that_matches_no_route_fails():
    with pytest.raises(AssertionError, match="exempt prefixes matched no route"):
        assert_module_gates(
            _app(gated=True),
            {"/api/v1/dld/": Feature.DLD},
            exempt_prefixes={"/api/v1/dld/internal/": ModuleExemption(reason=_REASON)},
        )


def test_an_exempt_prefix_outside_every_gate_prefix_fails():
    """Exempting something no gate reaches asserts nothing and hides a typo."""
    with pytest.raises(AssertionError, match="exempt prefixes not covered by any gate"):
        assert_module_gates(
            _app(gated=True),
            {"/api/v1/dld/": Feature.DLD},
            exempt_prefixes={"/api/v1/health/": ModuleExemption(reason=_REASON)},
        )


def test_an_exempt_route_that_authenticates_fails_the_claim():
    """The claim is re-verified every run: this is what stops an exemption from
    quietly covering a business route that lost its module gate."""
    with pytest.raises(AssertionError, match="resolves an AuthContext"):
        assert_module_gates(
            _app(gated=True, with_internal=True, internal_gated=True),
            {"/api/v1/dld/": Feature.DLD},
            exempt_prefixes={"/api/v1/dld/internal/": ModuleExemption(reason=_REASON)},
        )


def test_a_short_reason_is_rejected_at_construction():
    with pytest.raises(ValueError, match="must exceed"):
        ModuleExemption(reason="s2s")
