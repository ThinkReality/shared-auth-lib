"""The published API's "which routes are open" view comes from the enforcement list.

`/docs` is a security document. When it disagrees with the middleware, it is a
map that sends people to doors that are not there — tr-lead-management stamped
`BearerAuth` on everything, advertising bearer auth on its `/internal/*` subtree
(actually `X-Service-Token`), its `/public/*` site-key routes, and its health
probes, while a comment at the top of the very file said it existed "so the
schema builder and the gateway HMAC middleware share one source."

The derivation must go through `path_is_skipped`, never a reimplemented
`startswith`: that function is a three-branch mini-language (trailing `/` means
prefix, no slash means EXACT, `"/"` means root only), and a hand-rolled
substitute silently marks the entire service public.
"""

from __future__ import annotations

from fastapi import FastAPI

from shared_auth_lib.openapi import openapi_security_from_skip_paths

SKIP = [
    "/api/v1/health",
    "/api/v1/internal/",
    "/docs",
    "/",
]


def build_app() -> FastAPI:
    app = FastAPI(title="t", version="1")

    @app.get("/api/v1/health")
    async def health() -> dict:
        return {}

    @app.get("/api/v1/leads")
    async def leads() -> dict:
        return {}

    @app.post("/api/v1/internal/sync")
    async def internal_sync() -> dict:
        return {}

    @app.get("/api/v1/healthy-margin-report")
    async def near_miss() -> dict:
        return {}

    return app


def schema(**overrides) -> dict:
    app = build_app()
    kwargs = {
        "title": "t",
        "version": "1",
        "skip_paths": SKIP,
    }
    kwargs.update(overrides)
    return openapi_security_from_skip_paths(app, **kwargs)


def security_for(doc: dict, path: str, method: str = "get"):
    return doc["paths"][path][method].get("security")


def test_skipped_paths_are_marked_explicitly_public():
    """`security: []` rather than an absent key. Absent means "inherit the
    global default", which is not the same statement and reads as an oversight."""
    assert security_for(schema(), "/api/v1/health") == []


def test_enforced_paths_carry_the_credential_schemes():
    doc = schema()
    assert security_for(doc, "/api/v1/leads") == [
        {"BearerAuth": []},
        {"GatewaySignature": [], "GatewayTimestamp": []},
    ]


def test_not_public_paths_are_hmac_exempt_but_still_credentialed():
    """HMAC-exempt is not OpenAPI-public. An S2S subtree skips the gateway
    signature and still demands a service token at the route."""
    doc = schema(not_public=frozenset({"/api/v1/internal/"}))
    assert security_for(doc, "/api/v1/internal/sync", "post") != []


def test_exact_entries_do_not_match_by_prefix():
    """`/api/v1/health` has no trailing slash, so it is an EXACT match.
    A startswith() implementation would mark /api/v1/healthy-margin-report
    public too — this is the discriminating case that catches a reimplementation."""
    assert security_for(schema(), "/api/v1/healthy-margin-report") != []


def test_the_root_entry_does_not_exempt_the_whole_service():
    """Every real skip list contains "/". Treated as a prefix it matches every
    path in the service; `path_is_skipped` special-cases it to root only."""
    assert security_for(schema(), "/api/v1/leads") != []


def test_security_schemes_are_declared():
    components = schema()["components"]["securitySchemes"]
    assert components["BearerAuth"]["scheme"] == "bearer"
    assert components["GatewaySignature"]["in"] == "header"
    assert components["GatewayTimestamp"]["in"] == "header"


def test_repeat_calls_return_the_cached_schema():
    """FastAPI calls app.openapi() on every /openapi.json request."""
    app = build_app()
    first = openapi_security_from_skip_paths(
        app, title="t", version="1", skip_paths=SKIP
    )
    second = openapi_security_from_skip_paths(
        app, title="t", version="1", skip_paths=SKIP
    )
    assert first is second


def test_description_is_carried_through():
    assert schema(description="hello")["info"]["description"] == "hello"


def test_tag_descriptions_declared_on_the_app_survive():
    """FastAPI's own builder passes `self.openapi_tags`. A helper that omits
    them drops every tag description the service declared."""
    app = build_app()
    app.openapi_tags = [{"name": "Leads", "description": "Lead lifecycle"}]
    doc = openapi_security_from_skip_paths(
        app, title="t", version="1", skip_paths=SKIP
    )
    assert doc["tags"] == [{"name": "Leads", "description": "Lead lifecycle"}]


def test_not_public_paths_name_the_credential_they_actually_need():
    """They are gated by X-Service-Token, not by a bearer JWT or a gateway
    signature. Publishing the gateway schemes on them names the wrong
    credential — the narrower version of the lie this helper exists to fix."""
    doc = schema(not_public=frozenset({"/api/v1/internal/"}))
    assert security_for(doc, "/api/v1/internal/sync", "post") == [
        {"ServiceToken": []}
    ]
    assert doc["components"]["securitySchemes"]["ServiceToken"]["name"] == (
        "X-Service-Token"
    )
