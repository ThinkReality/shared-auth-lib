"""Fleet guard: every mounted route sits on exactly one auth surface.

Services mix routes that require auth with routes that must never have it inside
one router. A public router nested inside a gated router inherits the gate; a
business route mounted next to public ones loses it. Neither mistake is visible
at review time — the first shows up as a 401 on an anonymous page, the second as
an open door on a business one.

This lives in shared-auth-lib, not tr_shared.testing, because four of the five
families are defined by symbols shared-auth-lib owns: ``require_auth``,
``permission_names``, ``SystemRole``, ``path_is_skipped``. Putting it in
tr-shared-lib would mean injecting all four as arguments and releasing two
libraries in lockstep to ship one test helper. ``tr_shared/testing/__init__.py``
already states this rule for auth test helpers.

Five families, not seven buckets
--------------------------------
Seven detectors run; they collapse into five families, and it is the families
that must be disjoint. ``require_auth`` at the router level and
``require_permission`` on the route are both business — realty-hub's
``dld_router`` has exactly that shape, and a literal one-of-seven assertion
would fail it.

    business  — require_auth anywhere in the chain, or a permission/role gate
    site_key  — no AuthContext; tenant read through get_gateway_tenant_id.
                Gateway HMAC IS enforced: the visitor is anonymous, the CALLER
                is authenticated
    public    — the service's DECLARED public set (see below)
    s2s       — a service-token dependency in the chain
    webhook   — a provider-HMAC verifier in the chain, or a declared prefix

Routes are keyed by ``"{METHOD} {path}"``, not by path alone
--------------------------------------------------------------
``GET /x`` and ``POST /x`` are two independent ``APIRoute`` objects with
independent dependency chains. Keying anything by path alone collapses them —
whichever method's route object is visited last silently wins, and an
unguarded ``POST`` sitting next to an authenticated ``GET`` on the same path
becomes invisible. Every dict this module returns or accepts — the report, the
failure-message findings, the exemption map — is keyed by the method-qualified
label, never the bare path.

Three things this gets right that a first draft got wrong
---------------------------------------------------------
**The walk is recursive.** Services authenticate through bridge dependencies
(``get_current_user``, ``get_tenant_id``) that wrap ``require_auth`` one level
down. A depth-1 scan reported 29 crm-core routes and 2 media routes as
unguarded when every one of them was correctly gated.

**Permission detection reads only the ``_required_permissions`` marker
attribute — never closure cells.** ``require_permission`` and
``require_any_role`` set it on the callable they return; content-platform's
service-local ``has_permission`` already uses the same convention. An earlier
draft also inspected closure cells as a fallback, which meant any dependency
merely closing over a bare vocabulary string — e.g. an audit-tag helper
capturing the literal ``"admin"`` for a log line, with no auth check at all —
classified the route ``business`` with zero enforcement. The marker attribute
is opt-in and explicit; nothing can accidentally satisfy it.

**``public`` is the service's DECLARED set, not the raw skip list and not a
residual.** Every service skip-lists its internal prefix by design, because S2S
callers carry no gateway signature. If ``public`` meant "HMAC-skipped", every
internal route would sit on two families. If it meant "HMAC-skipped and nothing
else matched", an internal route that FORGOT its service-token dependency would
classify public — silently green, which is precisely the hole this guard exists
to find. So a service passes ``public_paths`` = its skip list minus every entry
that covers a guarded subtree, and passes the full ``hmac_skip_paths`` too, for
the overlap assertion below. ``SurfaceSpec`` itself asserts ``public_paths`` is
a subset of ``hmac_skip_paths`` — a declared public path that was never
actually skip-listed would otherwise make an unguarded route green with no
cross-check at all.

Known limitation, stated rather than hidden
-------------------------------------------
Only ``business``, ``site_key`` and ``s2s`` rest on route-level evidence.
``public`` and ``webhook`` rest partly on lists the service writes about itself,
so a route added under a declared webhook prefix classifies clean with no proof
that a verifier exists. Coverage is thinnest on the two surfaces where a mistake
is an open door. The skip-list side is covered independently by each service's
``test_hmac_skip_paths_ssot.py``; the webhook side is not covered by anything.

Usage, per service, in ``tests/architecture/test_route_surfaces.py``::

    # EVERY guarded subtree comes out of public_paths — not just the internal
    # one. Webhook prefixes are skip-listed too, so a spec that subtracts only
    # "/api/v1/internal/" leaves every webhook route classifying
    # {webhook, public} and fails a correct service. Subtract each prefix that
    # covers routes some other family is responsible for.
    GUARDED_SUBTREES = ("/api/v1/internal/", "/api/v1/webhooks/")

    SPEC = SurfaceSpec(
        public_paths=[p for p in HMAC_SKIP_PATHS if p not in GUARDED_SUBTREES],
        hmac_skip_paths=HMAC_SKIP_PATHS,
        s2s_callables=(validate_service_token,),
        webhook_prefixes=("/api/v1/webhooks/",),
    )

    def test_every_route_is_on_exactly_one_auth_surface():
        assert_route_surfaces(app, SPEC, EXEMPTIONS, minimum=40)

Exemption keys are ``"{METHOD} {path}"`` (e.g. ``"GET /api/v1/probe"``), the
same label the report and failure messages use — never a bare path, which
would silently exempt every method mounted at that path.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from shared_auth_lib.constants import SystemRole
from shared_auth_lib.dependencies.auth_dependencies import require_auth
from shared_auth_lib.middleware.hmac_middleware import path_is_skipped
from shared_auth_lib.permissions._registry import permission_names

__all__ = [
    "FAMILIES",
    "ModuleExemption",
    "RouteExemption",
    "SurfaceSpec",
    "assert_module_gates",
    "assert_route_surfaces",
    "classify_route",
    "route_surface_report",
]

FAMILIES: tuple[str, ...] = ("business", "site_key", "public", "s2s", "webhook")

_MIN_REASON_LENGTH = 60


def _gate_vocabulary() -> frozenset[str]:
    """Every string that proves a route is gated: permissions and system roles.

    Read lazily rather than at import, so a service that extends the permission
    registry in a conftest is not raced by module import order.
    """
    return frozenset(permission_names()) | {str(r) for r in SystemRole}


@dataclass(frozen=True)
class RouteExemption:
    """A permitted deviation, plus the machine-checkable claim that permits it.

    ``surfaces`` is the exact family set the route is allowed to have. It is a
    claim about what the route IS, not a mute button: if the route later gains
    or loses a surface, the exemption fails rather than quietly covering the new
    shape.
    """

    reason: str
    surfaces: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.reason) <= _MIN_REASON_LENGTH:
            raise ValueError(
                f"exemption reason must exceed {_MIN_REASON_LENGTH} chars — state "
                "what authenticates this route and why the standard shape does not fit"
            )
        unknown = sorted(set(self.surfaces) - set(FAMILIES))
        if unknown:
            raise ValueError(f"unknown families {unknown}; known: {list(FAMILIES)}")


@dataclass(frozen=True)
class SurfaceSpec:
    """One service's declarations. Everything here genuinely differs per service
    and cannot be inferred from the app object."""

    # The skip-list entries that mean "no auth of any kind". This is the full
    # skip list MINUS every entry covering a guarded subtree (typically the S2S
    # prefix). See the module docstring for why this is not the raw list.
    public_paths: Sequence[str]
    # The full enforcement list, for the gated-under-skip overlap assertion.
    hmac_skip_paths: Sequence[str]
    s2s_callables: tuple[Callable[..., Any], ...] = field(default=())
    webhook_callables: tuple[Callable[..., Any], ...] = field(default=())
    # Last resort: a webhook whose verification is not a dependency.
    webhook_prefixes: tuple[str, ...] = field(default=())
    # Service-local gates that expose neither a registry string nor require_auth.
    extra_business_callables: tuple[Callable[..., Any], ...] = field(default=())

    def __post_init__(self) -> None:
        extra = sorted(set(self.public_paths) - set(self.hmac_skip_paths))
        if extra:
            raise ValueError(
                f"public_paths entries not present in hmac_skip_paths: {extra}. "
                "A declared public path that was never actually skip-listed makes "
                "an unguarded route classify clean with no HMAC evidence behind it — "
                "public_paths must be a subset of hmac_skip_paths."
            )


def _flatten(dependant: Any) -> Iterator[Any]:
    """Every callable in the route's dependency tree, depth-first, once each.

    ``dependant.dependencies`` is ONE level. Bridge dependencies put
    ``require_auth`` below that, so a depth-1 walk misreads a correctly gated
    route as unguarded. The subtree of an already-seen callable is still
    descended — only the yield is deduped, not the walk — so a diamond-shaped
    dependency graph never silently drops a branch.
    """
    seen: set[int] = set()
    stack = list(dependant.dependencies)
    while stack:
        dep = stack.pop()
        call = getattr(dep, "call", None)
        stack.extend(getattr(dep, "dependencies", ()) or ())
        if call is not None:
            key = id(call)
            if key in seen:
                continue
            seen.add(key)
            yield call


def _declares_a_gate(call: Any, vocabulary: frozenset[str]) -> bool:
    """A permission or role gate, via the ``_required_permissions`` marker
    attribute set by ``require_permission``/``require_any_role`` and by
    service-local gates using the same convention (e.g. content-platform's
    ``has_permission``). Closure cells are never inspected: a dependency that
    merely closes over a bare vocabulary string — with no gate behind it —
    must not be mistaken for one.
    """

    def _matches(value: Any) -> bool:
        if isinstance(value, str):
            return value in vocabulary
        if isinstance(value, (list, tuple, set, frozenset)):
            return any(isinstance(v, str) and v in vocabulary for v in value)
        return False

    return _matches(getattr(call, "_required_permissions", None))


def _scannable_routes(app: Any) -> Iterator[Any]:
    """Service routes only.

    Starlette's own ``/docs``/``/redoc``/``/openapi.json``/``/docs/oauth2-redirect``
    are plain Routes with no ``dependant``, and a ``StaticFiles`` mount has none
    either — so this filter drops both without naming them.
    """
    for route in app.routes:
        if getattr(route, "path", None) is None:
            continue
        if not hasattr(route, "dependant"):
            continue
        yield route


def _route_label(route: Any) -> str:
    """``"{METHOD} {path}"`` — the method-qualified key every dict in this
    module uses. Never key by bare path: two methods on one path are two
    routes with independent dependency chains.

    ``APIWebSocketRoute`` has ``dependant`` (so it passes ``_scannable_routes``)
    but no ``methods`` attribute — it falls back to the literal ``"WS"`` so a
    websocket route never produces an empty, leading-space method segment.
    """
    methods = ",".join(sorted(getattr(route, "methods", None) or ())) or "WS"
    return f"{methods} {route.path}"


def classify_route(route: Any, spec: SurfaceSpec) -> frozenset[str]:
    """The families this route matches. Empty means it is on no surface."""
    from tr_shared.web.dependencies import get_gateway_tenant_id

    path: str = route.path
    calls = list(_flatten(route.dependant))
    vocabulary = _gate_vocabulary()
    families: set[str] = set()

    if (
        require_auth in calls
        or any(call in spec.extra_business_callables for call in calls)
        or any(_declares_a_gate(call, vocabulary) for call in calls)
    ):
        families.add("business")

    if get_gateway_tenant_id in calls:
        families.add("site_key")

    if any(call in spec.s2s_callables for call in calls):
        families.add("s2s")

    webhook_prefix_paths = [p.rstrip("/") + "/" for p in spec.webhook_prefixes]
    if any(call in spec.webhook_callables for call in calls) or (
        not families and path_is_skipped(path, webhook_prefix_paths)
    ):
        families.add("webhook")

    if path_is_skipped(path, list(spec.public_paths)):
        families.add("public")

    return frozenset(families)


def route_surface_report(app: Any, spec: SurfaceSpec) -> dict[str, frozenset[str]]:
    """``"{METHOD} {path}"`` → families, for diagnostics and for the fleet
    verification step. Method-qualified so two methods on one path never
    collapse into a single, last-wins entry."""
    return {
        _route_label(route): classify_route(route, spec)
        for route in _scannable_routes(app)
    }


def assert_route_surfaces(
    app: Any,
    spec: SurfaceSpec,
    exemptions: Mapping[str, RouteExemption],
    minimum: int,
) -> None:
    """The whole guard. One call so a wrapper cannot silently omit a check.

    Seven assertions:
      1. enough routes were scanned      — a wrong app import makes the rest vacuous
      2. no two routes share a method+path label — a colliding label would
         silently drop one route's classification from every check below
      3. every route on exactly one family
      4. no gated route under an HMAC-skipped prefix
      5. exemptions match the surfaces they claim
      6. at least one business route     — a drifted registry makes the rest vacuous
      7. no exemption for a route that no longer exists

    Iterates route OBJECTS, not a path-keyed dict — two methods on the same
    path are two independent routes and must never collapse into one finding.
    Every list below is built from ``_route_label(route)`` (``"METHOD path"``),
    so a failure message always names the method, and an exemption never
    silently covers every method mounted at a path. ``report`` (the label →
    families map used by the inert check and returned to the caller in spirit)
    is built by calling ``route_surface_report`` — the single place that logic
    lives — rather than a second, hand-rolled dict comprehension here.

    The HMAC-leak check (4) runs BEFORE the exemption's ``continue``: an
    exemption's ``surfaces`` claim is about family membership only, and makes
    no claim about HMAC coverage — an exempted business route sitting under a
    skipped prefix is still a full auth bypass and must still fail.

    The inert check (6) runs after the concrete per-route findings (3-5) so a
    single unguarded route reports "no auth surface", not "your suite proves
    nothing" — a concrete finding is more actionable than a vacuity warning.
    """
    routes = list(_scannable_routes(app))
    assert len(routes) >= minimum, (
        f"only {len(routes)} scannable routes found, expected at least {minimum}. "
        "The app import is probably wrong — every assertion below would pass vacuously."
    )

    labels = [_route_label(route) for route in routes]
    report = route_surface_report(app, spec)
    if len(report) != len(routes):
        duplicates = sorted({label for label in labels if labels.count(label) > 1})
        raise AssertionError(
            f"{len(routes)} routes scanned but only {len(report)} distinct "
            f"method+path labels produced. Duplicate route registrations "
            f"{duplicates} collapse into one report entry each, hiding whichever "
            "route classified differently. Two routes must never share a method "
            "and path — check for a router included twice or two routers "
            "mounting the same path."
        )

    unguarded: list[str] = []
    overlapping: list[str] = []
    mismatched: list[str] = []
    leaked: list[str] = []

    for route in routes:
        label = _route_label(route)
        families = report[label]

        if families & {"business", "site_key"} and path_is_skipped(
            route.path, list(spec.hmac_skip_paths)
        ):
            leaked.append(label)

        exemption = exemptions.get(label)
        if exemption is not None:
            if families != frozenset(exemption.surfaces):
                mismatched.append(
                    f"{label}: exemption claims surfaces {sorted(exemption.surfaces)}, "
                    f"route actually has {sorted(families)}"
                )
            continue

        if not families:
            unguarded.append(label)
        elif len(families) > 1:
            overlapping.append(f"{label}: {sorted(families)}")

    assert not unguarded, (
        f"Routes on no auth surface: {sorted(set(unguarded))}. Mount under the "
        "module's business router (require_auth / require_permission), the public "
        "router (site-key tier), the internal router (service token) or the webhook "
        "router — or add a RouteExemption stating what protects it."
    )
    assert not overlapping, (
        f"Routes on more than one auth surface: {sorted(set(overlapping))}. A public "
        "router nested inside a gated one inherits the gate; mount it as a SIBLING."
    )
    assert not leaked, (
        f"Gated routes under an HMAC-skipped prefix: {sorted(set(leaked))}. "
        "require_auth would build an AuthContext from unverified X-User-* headers — "
        "a full auth bypass. Either remove the skip entry or move the route. An "
        "exemption does not silence this: it claims family membership, not HMAC "
        "coverage."
    )
    assert not mismatched, (
        "Exemption claims surfaces that no longer match:\n"
        + "\n".join(sorted(mismatched))
    )

    assert any("business" in f for f in report.values()), (
        "no route classified as business — the gate detectors matched nothing, so "
        "this guard proves nothing. Check that the permission registry is populated."
    )

    stale = sorted(set(exemptions) - set(report))
    assert not stale, (
        f"Exemptions for routes that are no longer mounted: {stale}. Delete them — an "
        "exemption that outlives its route is a permanent hole waiting for a future "
        "route to reuse the path."
    )


@dataclass(frozen=True)
class ModuleExemption:
    """A path subtree the entitlement gate does not reach, plus its justification.

    Keys a PREFIX, never a route label. "The site-key tier under
    ``/api/v1/listing/public`` is not an entitlement surface" is a rule that covers
    the route added there tomorrow; a list of today's route labels is an inventory
    that silently stops covering anything.

    The claim it makes is FIXED and re-verified on every run: **no route under this
    prefix resolves an AuthContext.** There is no settable ``authenticated`` flag —
    a claim the caller can dial is a mute button, and the one thing an exemption
    must never do is quietly cover an authenticated business route that lost its
    module gate.

    That claim is the honest form of the enforcement boundary. Entitlement is an
    authenticated-API gate. It is NOT that ingest paths have no tenant: lead
    management resolves a tenant from ``X-Site-Key`` on its public forms and from
    ``_resolve_tenant`` on its portal webhooks. It is that those paths are out of
    scope by decision — see the plan's Architecture section.
    """

    reason: str

    def __post_init__(self) -> None:
        if len(self.reason) <= _MIN_REASON_LENGTH:
            raise ValueError(
                f"exemption reason must exceed {_MIN_REASON_LENGTH} chars — state "
                "which auth surface this subtree is on and why an entitlement gate "
                "does not belong there"
            )


def _required_modules(route: Any) -> frozenset[Any]:
    """Every module named by a `require_module` gate in this route's chain.

    Reuses `_flatten` — services gate at the router, so the marker sits above the
    route in the dependency tree, and a depth-1 scan would miss every one of them.
    """
    found: set[Any] = set()
    for call in _flatten(route.dependant):
        found.update(getattr(call, "_required_modules", ()) or ())
    return frozenset(found)


def assert_module_gates(
    app: Any,
    gates: Mapping[str, Any],
    exempt_prefixes: Mapping[str, ModuleExemption] | None = None,
) -> None:
    """Every route under a declared prefix carries that prefix's module gate.

    ``gates`` maps a path prefix to the ``Feature`` that owns it. This encodes a
    RULE — a prefix owns a module — not an inventory of today's routes, so a route
    added under the prefix tomorrow is covered with no edit here.

    There is deliberately NO fleet-wide "every business route needs a gate"
    assertion: most business routers (auth, admin, activity, notification, task)
    are not entitlement units, and a version of this that listed them would be an
    instance list pretending to be an invariant.

    Four assertions, each of which exists because its absence makes another vacuous:

      1. every gate prefix matched at least one route — a typo'd prefix asserts
         nothing
      2. every exempt prefix matched at least one route, and sits under some gate
         prefix — an exemption for a subtree no gate reaches asserts nothing either
      3. every exempt route's claim holds: no ``require_auth`` in its chain
      4. every remaining route under a gate prefix carries that module's marker

    Prefix matching is a plain ``str.startswith`` on the declared prefixes, which
    is why every prefix in this plan is written out in full. It deliberately does
    NOT derive prefixes from ``HMAC_SKIP_PATHS``: that list contains ``"/"``, and
    ``"/".rstrip("/") == ""`` makes ``startswith("")`` true for every path in the
    service — one line that silently exempts everything and turns this whole guard
    green with zero coverage.
    """
    exempt_prefixes = exempt_prefixes or {}
    ungated: list[str] = []
    authenticated_exempt: list[str] = []
    matched: dict[str, int] = {prefix: 0 for prefix in gates}
    exempt_matched: dict[str, int] = {prefix: 0 for prefix in exempt_prefixes}

    uncovered = sorted(
        ex
        for ex in exempt_prefixes
        if not any(ex.startswith(gate) for gate in gates)
    )
    assert not uncovered, (
        f"exempt prefixes not covered by any gate prefix: {uncovered}. An exemption "
        "for a subtree no gate reaches excuses nothing and hides a typo — drop it, "
        "or fix the prefix so it sits under the gate it is excusing."
    )

    for route in _scannable_routes(app):
        label = _route_label(route)
        exempt = next(
            (p for p in exempt_prefixes if route.path.startswith(p)), None
        )
        if exempt is not None:
            exempt_matched[exempt] += 1
            if require_auth in _flatten(route.dependant):
                authenticated_exempt.append(f"{label} (exempt prefix {exempt})")
            continue

        for prefix, module in gates.items():
            if not route.path.startswith(prefix):
                continue
            matched[prefix] += 1
            if module not in _required_modules(route):
                ungated.append(f"{label}: missing require_module({module.value})")

    empty = sorted(p for p, n in matched.items() if n == 0)
    assert not empty, (
        f"module-gate prefixes matched no route: {empty}. A prefix that matches "
        "nothing asserts nothing — fix the prefix or drop the entry."
    )

    empty_exempt = sorted(p for p, n in exempt_matched.items() if n == 0)
    assert not empty_exempt, (
        f"exempt prefixes matched no route: {empty_exempt}. Delete them — an "
        "exemption that matches nothing is either a typo or a hole waiting for a "
        "future route to reuse the path."
    )

    assert not authenticated_exempt, (
        "Exempt prefix resolves an AuthContext on these routes:\n"
        + "\n".join(sorted(authenticated_exempt))
        + "\n\nThe exemption claims this subtree is not an authenticated surface, "
        "and it is. Either the route belongs under the gated router (add "
        "require_module), or the exemption is wrong. Entitlement gates every "
        "authenticated business route — there is no opt-out for one that simply "
        "lost its gate."
    )

    assert not ungated, (
        "Routes under an entitlement-owned prefix with no module gate:\n"
        + "\n".join(sorted(ungated))
        + "\n\nAdd Depends(require_module(Feature.X)) to the router that owns the "
        "prefix — not to individual handlers. A gate declared in two places can be "
        "deleted from one with nothing failing."
    )
