"""One OpenAPI security view, derived from the one enforcement list.

`/docs` is a security document, and when it disagrees with the middleware it
misleads exactly the people who consult it. Four variants existed:
tr-content-platform and tr-people-finance each independently hand-rolled the
same ~20-line derivation; tr-lead-management stamped a blanket `BearerAuth` on
every route and never read its own skip list — advertising bearer auth on its
`/internal/*` subtree (really `X-Service-Token`), on its `/public/*` site-key
routes, and on its health probes; and crm-core, media, realty-hub and WAM
published no security information at all.

The output here is one model for the fleet, not a superset of the old ones.
tr-content-platform's schema therefore CHANGES on adoption: it gains an explicit
`security: []` on skipped paths (rather than an absent key) and the two gateway
header schemes. That is the fix, not a regression — reproducing both prior
behaviours would have meant re-creating the divergence inside the shared
function.

`path_is_skipped` does the matching. Never reimplement it: it is a three-branch
mini-language — a trailing `/` prefix-matches, no trailing slash matches
EXACTLY, and `"/"` matches the root only. Every real skip list contains `"/"`,
so a `startswith` substitute marks the whole service public.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from fastapi.openapi.utils import get_openapi
from tr_shared.contracts.headers import HttpHeader

from shared_auth_lib.middleware.hmac_middleware import path_is_skipped

__all__ = ["openapi_security_from_skip_paths"]

_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})

_SCHEMES: dict[str, dict[str, Any]] = {
    "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": ("Frontend JWT accepted by the API gateway before routing."),
    },
    "GatewaySignature": {
        "type": "apiKey",
        "in": "header",
        "name": HttpHeader.GATEWAY_SIGNATURE.value,
        "description": (
            "HMAC signature added by the API gateway for downstream calls."
        ),
    },
    "GatewayTimestamp": {
        "type": "apiKey",
        "in": "header",
        "name": HttpHeader.GATEWAY_TIMESTAMP.value,
        "description": "ISO timestamp used by gateway HMAC verification.",
    },
}

_CREDENTIALED: list[dict[str, list[str]]] = [
    {"BearerAuth": []},
    {"GatewaySignature": [], "GatewayTimestamp": []},
]


def openapi_security_from_skip_paths(
    app: Any,
    *,
    title: str,
    version: str,
    skip_paths: Sequence[str],
    not_public: frozenset[str] = frozenset(),
    description: str = "",
) -> dict[str, Any]:
    """Build (and cache on `app`) an OpenAPI schema whose security matches HMAC.

    Assign it as the app's builder:

        app.openapi = lambda: openapi_security_from_skip_paths(
            app, title=..., version=..., skip_paths=HMAC_SKIP_PATHS
        )

    Args:
        skip_paths: The service's `HMAC_SKIP_PATHS` — the SAME list the
            middleware enforces, not a second copy written for the docs.
        not_public: Entries of `skip_paths` that skip HMAC but still require
            another credential at the route layer (an `X-Service-Token` S2S
            subtree). HMAC-exempt is not the same as open, and conflating them
            is how an S2S surface comes to be documented as public.

    Returns:
        The schema, also stored on `app.openapi_schema`. A second call returns
        the cached object — FastAPI invokes the builder on every
        `/openapi.json` request.
    """
    cached = getattr(app, "openapi_schema", None)
    if cached:
        return cached  # type: ignore[no-any-return]

    schema = get_openapi(
        title=title,
        version=version,
        description=description,
        routes=app.routes,
    )

    public = [p for p in skip_paths if p not in not_public]

    schema.setdefault("components", {})["securitySchemes"] = dict(_SCHEMES)

    for path, operations in schema.get("paths", {}).items():
        is_public = path_is_skipped(path, public)
        for name, spec in operations.items():
            if not isinstance(spec, dict) or name.lower() not in _METHODS:
                continue
            spec["security"] = [] if is_public else list(_CREDENTIALED)

    app.openapi_schema = schema
    return schema
