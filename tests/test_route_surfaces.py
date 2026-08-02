"""Self-tests for the fleet route-surface guard.

Toy apps only — no service imports. Seven services will trust this helper
without re-deriving its logic, so it must be provably correct here.

`path_is_skipped` below is the REAL function, imported. An earlier draft
hand-rolled a prefix-matching stand-in, which behaves nothing like the real
three-branch rule and marked every route public while all tests stayed green.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI, Request, WebSocket
import pytest

from shared_auth_lib import require_any_role, require_auth, require_permission
from shared_auth_lib.middleware.hmac_middleware import path_is_skipped
from shared_auth_lib.permissions._registry import permission_names
from shared_auth_lib.testing import (
    RouteExemption,
    SurfaceSpec,
    assert_route_surfaces,
    classify_route,
    route_surface_report,
)
from tr_shared.web.dependencies import get_gateway_tenant_id

A_PERMISSION = sorted(permission_names())[0]

SKIP = ["/", "/docs", "/api/v1/health", "/api/v1/internal/"]
PUBLIC = ["/", "/docs", "/api/v1/health"]  # skip list minus the guarded subtree


async def validate_service_token(request: Request) -> bool:
    return True


async def verify_provider_hmac(request: Request) -> None:
    return None


async def bridge_get_current_user(ctx=Depends(require_auth)):
    """Mirrors the real service bridges: require_auth sits one level DOWN."""
    return ctx


def service_local_permission_gate(names: list[str]):
    """Mirrors content-platform's has_permission: the closure holds a LIST, and
    the readable claim is an attribute."""

    async def _checker(user=Depends(bridge_get_current_user)):
        return user

    _checker._required_permissions = tuple(names)
    return _checker


def bare_permission_gate(names: list[str]):
    """Same attribute hook, no sub-dependency — isolates the vocabulary check
    from the require_auth detector."""

    async def _checker() -> None:
        return None

    _checker._required_permissions = tuple(names)
    return _checker


def _spec(**overrides) -> SurfaceSpec:
    base = dict(
        public_paths=PUBLIC,
        hmac_skip_paths=SKIP,
        s2s_callables=(validate_service_token,),
        webhook_callables=(verify_provider_hmac,),
        webhook_prefixes=(),
        extra_business_callables=(),
    )
    base.update(overrides)
    return SurfaceSpec(**base)


def _app(router: APIRouter, prefix: str = "") -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix=prefix)
    return app


def _route(app: FastAPI, path: str):
    return next(r for r in app.routes if getattr(r, "path", None) == path)


def _one(router: APIRouter, path: str, spec: SurfaceSpec | None = None):
    app = _app(router)
    return classify_route(_route(app, path), spec or _spec())


# ── the real path_is_skipped contract, which a hand-rolled toy gets wrong ──


def test_real_skip_semantics_exact_vs_prefix():
    assert path_is_skipped("/api/v1/health", SKIP)
    assert not path_is_skipped(
        "/api/v1/health/ready", SKIP
    )  # no trailing slash = EXACT
    assert path_is_skipped("/api/v1/internal/x", SKIP)  # trailing slash = PREFIX
    assert not path_is_skipped("/api/v1/internalize", SKIP)
    assert path_is_skipped("/", SKIP)
    assert not path_is_skipped("/anything", SKIP)  # "/" is root ONLY


# ── business ──


def test_require_auth_is_business():
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get("/api/v1/employees")
    async def employees() -> dict:
        return {}

    assert _one(r, "/api/v1/employees") == {"business"}


def test_require_permission_is_business():
    r = APIRouter()

    @r.get(
        "/api/v1/listings", dependencies=[Depends(require_permission(A_PERMISSION))]
    )
    async def listings() -> dict:
        return {}

    assert _one(r, "/api/v1/listings") == {"business"}


def test_require_any_role_is_business():
    """crm-core role-gates more than it permission-gates. require_any_role
    closes over a LIST of SystemRole values, not permission names."""
    r = APIRouter()

    @r.get(
        "/api/v1/users", dependencies=[Depends(require_any_role(["super_admin"]))]
    )
    async def users() -> dict:
        return {}

    assert _one(r, "/api/v1/users") == {"business"}


def test_auth_through_a_bridge_dependency_is_business():
    """Depth-1 scanning reported 29 crm-core and 2 media routes as unguarded.
    require_auth is a SUB-dependency of the service's own bridge."""
    r = APIRouter()

    @r.get("/api/v1/usage/storage")
    async def usage(user=Depends(bridge_get_current_user)) -> dict:
        return {}

    assert _one(r, "/api/v1/usage/storage") == {"business"}


def test_service_local_gate_declaring_required_permissions_is_business():
    """content-platform's has_permission closes over a LIST — isinstance(str)
    misses it — and mints a fresh closure per call site, so the callable cannot
    be enumerated. The attribute it already sets is the reliable hook."""
    gate = bare_permission_gate([A_PERMISSION])
    r = APIRouter()

    @r.get("/api/v1/listings/{listing_id}", dependencies=[Depends(gate)])
    async def one() -> dict:
        return {}

    assert _one(r, "/api/v1/listings/{listing_id}") == {"business"}


def test_auth_and_permission_together_are_one_family():
    """realty-hub's dld_router: router-level require_auth AND per-route
    require_permission. Two detectors, one family — a literal one-of-seven
    assertion would fail this correct route."""
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get(
        "/api/v1/dld/areas", dependencies=[Depends(require_permission(A_PERMISSION))]
    )
    async def areas() -> dict:
        return {}

    assert _one(r, "/api/v1/dld/areas") == {"business"}


def test_a_string_not_in_the_registry_does_not_count():
    """Never match on `":" in value` — a dependency closing over a URL, a Redis
    key or a content type would read as permission-gated."""
    gate = bare_permission_gate(["redis:cache:key"])
    r = APIRouter()

    @r.get("/api/v1/oops", dependencies=[Depends(gate)])
    async def oops() -> dict:
        return {}

    assert _one(r, "/api/v1/oops") == frozenset()


# ── the other four families ──


def test_site_key_tier():
    r = APIRouter()

    @r.get("/api/v1/cms/public/blogs")
    async def blogs(tenant=Depends(get_gateway_tenant_id)) -> dict:
        return {}

    assert _one(r, "/api/v1/cms/public/blogs") == {"site_key"}


def test_declared_public_path():
    r = APIRouter()

    @r.get("/api/v1/health")
    async def health() -> dict:
        return {}

    assert _one(r, "/api/v1/health") == {"public"}


def test_s2s_route_under_a_skipped_prefix_is_s2s_only_not_public():
    """Every service skip-lists its internal prefix by design — S2S callers
    carry no gateway signature. Adding `public` here would put every internal
    route on two families and no guard could ever go green."""
    r = APIRouter(dependencies=[Depends(validate_service_token)])

    @r.get("/api/v1/internal/leads")
    async def internal() -> dict:
        return {}

    assert _one(r, "/api/v1/internal/leads") == {"s2s"}


def test_an_internal_route_that_forgot_its_gate_is_NOT_public():
    """The hole the guard exists to find. If `public` were the residual of the
    raw skip list, a forgotten service-token dependency would classify public —
    silently green. The declared public set excludes the guarded subtree."""
    r = APIRouter()

    @r.get("/api/v1/internal/oops")
    async def oops() -> dict:
        return {}

    assert _one(r, "/api/v1/internal/oops") == frozenset()


def test_webhook_by_verifier_callable():
    r = APIRouter()

    @r.post(
        "/api/v1/webhooks/propertyfinder",
        dependencies=[Depends(verify_provider_hmac)],
    )
    async def pf() -> dict:
        return {}

    assert _one(r, "/api/v1/webhooks/propertyfinder") == {"webhook"}


def test_an_admin_route_inside_the_webhook_prefix_stays_business():
    """/webhooks/{event_id}/replays is a permission-gated operator endpoint
    living inside the webhook router. A path-prefix detector calls it
    {business, webhook} and fails a correct route."""
    r = APIRouter()

    @r.post(
        "/api/v1/webhooks/{event_id}/replays",
        dependencies=[Depends(require_permission(A_PERMISSION))],
    )
    async def replay() -> dict:
        return {}

    spec = _spec(webhook_prefixes=("/api/v1/webhooks",))
    assert _one(r, "/api/v1/webhooks/{event_id}/replays", spec) == {"business"}


# ── the assertions ──


def test_unguarded_route_fails():
    r = APIRouter()

    @r.get("/api/v1/forgotten")
    async def forgotten() -> dict:
        return {}

    with pytest.raises(AssertionError, match="no auth surface"):
        assert_route_surfaces(_app(r), _spec(), {}, minimum=1)


def test_route_on_two_families_fails():
    """realty-hub's authed /health: declared public AND behind require_auth."""
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get("/api/v1/health")
    async def health() -> dict:
        return {}

    with pytest.raises(AssertionError, match="more than one auth surface"):
        assert_route_surfaces(_app(r), _spec(), {}, minimum=1)


def test_a_gated_route_under_an_hmac_skipped_prefix_fails():
    """Not subsumed by the family count. A permission-gated route under a
    skipped prefix classifies as exactly one family (business) — yet
    require_auth would build an AuthContext from unverified X-User-* headers.
    Full auth bypass. WAM's guard caught this; the family model does not."""
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get("/api/v1/internal/leaked")
    async def leaked() -> dict:
        return {}

    with pytest.raises(AssertionError, match="HMAC-skipped"):
        assert_route_surfaces(_app(r), _spec(), {}, minimum=1)


def test_a_suite_with_no_business_route_fails_as_inert():
    """If the permission registry drifts and every detector stops matching,
    a guard over only public routes passes forever and proves nothing."""
    r = APIRouter()

    @r.get("/api/v1/health")
    async def health() -> dict:
        return {}

    with pytest.raises(AssertionError, match="no route classified as business"):
        assert_route_surfaces(_app(r), _spec(), {}, minimum=1)


def test_minimum_catches_a_wrong_app_import():
    with pytest.raises(AssertionError, match="only .* routes"):
        assert_route_surfaces(FastAPI(), _spec(), {}, minimum=5)


def test_exemption_permits_exactly_the_surfaces_it_claims():
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get("/api/v1/gated")
    async def gated() -> dict:
        return {}

    @r.get("/api/v1/probe")
    async def probe() -> dict:
        return {}

    exemptions = {
        "GET /api/v1/probe": RouteExemption(
            reason=(
                "Authenticated via the same require_auth chain as every other route "
                "in this router; exempted here only to exercise the exemption "
                "machinery in this self-test, not because the route lacks auth."
            ),
            surfaces=("business",),
        )
    }
    assert_route_surfaces(_app(r), _spec(), exemptions, minimum=1)


def test_exemption_claiming_the_wrong_surfaces_still_fails():
    """Uses a path outside the HMAC skip list so the mismatch is isolated from
    the (separate) leak check exercised above."""
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get("/api/v1/not-skipped")
    async def not_skipped() -> dict:
        return {}

    exemptions = {
        "GET /api/v1/not-skipped": RouteExemption(
            reason="x" * 61, surfaces=("public",)
        )
    }
    with pytest.raises(AssertionError, match="claims surfaces"):
        assert_route_surfaces(_app(r), _spec(), exemptions, minimum=1)


def test_stale_exemption_fails():
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get("/api/v1/here")
    async def here() -> dict:
        return {}

    exemptions = {
        "GET /api/v1/deleted": RouteExemption(reason="y" * 61, surfaces=())
    }
    with pytest.raises(AssertionError, match="no longer mounted"):
        assert_route_surfaces(_app(r), _spec(), exemptions, minimum=1)


def test_a_short_reason_is_rejected():
    with pytest.raises(ValueError, match="reason"):
        RouteExemption(reason="because", surfaces=())


def test_unknown_family_in_an_exemption_is_rejected():
    with pytest.raises(ValueError, match="unknown families"):
        RouteExemption(reason="z" * 61, surfaces=("bogus",))


def test_report_maps_every_scanned_route_by_method_qualified_label():
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get("/api/v1/employees")
    async def employees() -> dict:
        return {}

    assert route_surface_report(_app(r), _spec())["GET /api/v1/employees"] == {
        "business"
    }


# ── Critical 1: multi-method routes must not collapse by path ──


def test_multi_method_routes_on_one_path_do_not_collapse():
    """Reviewer's exact reproduction: an unguarded POST sitting next to an
    authenticated GET on the same path must not be hidden by a path-keyed
    dict where the last-registered method silently wins."""
    r = APIRouter()

    @r.post("/api/v1/listings")
    async def create_listing() -> dict:
        return {}

    @r.get("/api/v1/listings", dependencies=[Depends(require_auth)])
    async def list_listings() -> dict:
        return {}

    app = _app(r)
    report = route_surface_report(app, _spec())
    assert report["POST /api/v1/listings"] == frozenset()
    assert report["GET /api/v1/listings"] == {"business"}

    with pytest.raises(AssertionError, match="POST /api/v1/listings"):
        assert_route_surfaces(app, _spec(), {}, minimum=2)


def test_exemption_on_one_method_does_not_cover_the_other():
    """A path-only exemption would be a mute button covering every method
    mounted at that path. Exempting GET must leave the unguarded POST caught."""
    r = APIRouter()

    @r.post("/api/v1/listings")
    async def create_listing() -> dict:
        return {}

    @r.get("/api/v1/listings", dependencies=[Depends(require_auth)])
    async def list_listings() -> dict:
        return {}

    exemptions = {
        "GET /api/v1/listings": RouteExemption(
            reason="x" * 61, surfaces=("business",)
        )
    }
    with pytest.raises(AssertionError, match="no auth surface"):
        assert_route_surfaces(_app(r), _spec(), exemptions, minimum=2)


# ── Critical 2: bare vocabulary strings must not be enough ──


def test_a_closure_over_the_bare_string_admin_is_not_business():
    """require_permission/require_any_role set _required_permissions
    explicitly; nothing else does. A dependency that merely closes over the
    literal "admin" — e.g. an audit-tag helper with no enforcement at all —
    must not be mistaken for a role gate."""

    def audit_tag(schema: str):
        async def _dep() -> str:
            return schema

        return _dep

    r = APIRouter()

    @r.get(
        "/api/v1/totally-unguarded",
        dependencies=[Depends(audit_tag("admin"))],
    )
    async def unguarded() -> dict:
        return {}

    assert _one(r, "/api/v1/totally-unguarded") == frozenset()


# ── Critical 3: an exemption makes no claim about HMAC coverage ──


def test_exempted_route_under_hmac_skipped_prefix_still_fails():
    """RouteExemption.surfaces is a claim about family membership only. A
    business route exempted with surfaces=("business",) has said nothing
    about HMAC coverage — it is still a full auth bypass if mounted under a
    skipped prefix."""
    r = APIRouter(dependencies=[Depends(require_auth)])

    @r.get("/api/v1/internal/leaked")
    async def leaked() -> dict:
        return {}

    exemptions = {
        "GET /api/v1/internal/leaked": RouteExemption(
            reason="x" * 61, surfaces=("business",)
        )
    }
    with pytest.raises(AssertionError, match="HMAC-skipped"):
        assert_route_surfaces(_app(r), _spec(), exemptions, minimum=1)


# ── Important 4: webhook_prefixes uses the real skip-list mini-language ──


def test_webhook_prefix_is_not_a_bare_startswith():
    """/api/v1/webhooksomething shares the character prefix "/api/v1/webhooks"
    with no "/" boundary after it — a bare `str.startswith` would match this
    unrelated, unguarded path and classify it webhook. The real skip-list
    mini-language requires a "/" boundary (or an exact match) before treating
    it as covered."""
    r = APIRouter()

    @r.get("/api/v1/webhooksomething")
    async def lookalike() -> dict:
        return {}

    spec = _spec(webhook_prefixes=("/api/v1/webhooks",))
    assert _one(r, "/api/v1/webhooksomething", spec) == frozenset()


def test_webhook_prefix_matches_a_real_subpath():
    r = APIRouter()

    @r.get("/api/v1/webhooks/bayut")
    async def bayut() -> dict:
        return {}

    spec = _spec(webhook_prefixes=("/api/v1/webhooks",))
    assert _one(r, "/api/v1/webhooks/bayut", spec) == {"webhook"}


# ── Important 5: public_paths must be a subset of hmac_skip_paths ──


def test_public_path_not_in_skip_list_is_rejected():
    with pytest.raises(ValueError, match="public_paths entries not present"):
        SurfaceSpec(
            public_paths=["/api/v1/not-actually-skipped"],
            hmac_skip_paths=SKIP,
        )


# ── report/assertion parity: a colliding method+path label must not hide a route ──


def test_duplicate_method_path_label_is_rejected_not_silently_collapsed():
    """Two routers each mounting GET /api/v1/dup produce two distinct route
    OBJECTS sharing one method+path label. A silent dict collapse here would
    make route_surface_report undercount while the per-route finding lists
    (built from a list, not a dict) still happened to catch it — an accident,
    not a guarantee. This must fail loudly instead."""
    gated = APIRouter(dependencies=[Depends(require_auth)])

    @gated.get("/api/v1/dup")
    async def a() -> dict:
        return {}

    ungated = APIRouter()

    @ungated.get("/api/v1/dup")
    async def b() -> dict:
        return {}

    app = FastAPI()
    app.include_router(gated)
    app.include_router(ungated)

    with pytest.raises(AssertionError, match="distinct method\\+path labels"):
        assert_route_surfaces(app, _spec(), {}, minimum=2)


def test_websocket_route_label_has_no_leading_space():
    """APIWebSocketRoute has `dependant` (so it's scanned) but no `methods`
    attribute. Without a fallback, the label collapses to " {path}" — a
    leading space and an empty method segment — rather than aborting or
    colliding, this must produce a distinct, readable "WS {path}" label."""
    app = FastAPI()

    @app.websocket("/api/v1/ws/notifications")
    async def ws(websocket: WebSocket) -> None:
        return None

    report = route_surface_report(app, _spec())
    assert "WS /api/v1/ws/notifications" in report
    assert not any(label.startswith(" ") for label in report)
