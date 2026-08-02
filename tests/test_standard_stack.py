"""The request stack has one assembly order, and it lives in one function.

Every assertion here reads the EFFECTIVE order off `app.user_middleware`, never
the source order of the calls. Reading source order is exactly the mistake that
put tr-media-service's stack in reverse: `main.py` carried the comment
"First added = outermost", which is backwards — Starlette's `add_middleware`
inserts at position 0, so the LAST added is outermost. The comment's intent was
right and the code did the opposite for months, invisibly, because dev compose
sets AUTH_LIB_DEV_MODE_BYPASS=true.

index 0 == outermost == first to see the request.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

from shared_auth_lib.middleware import Slot, install_standard_middleware

SECRET = "test-secret"


class _Marker(BaseHTTPMiddleware):
    """Stand-in for a service's own middleware in an `extras` slot."""


class _OtherMarker(BaseHTTPMiddleware):
    pass


class _FakeRedis:
    async def set(self, *args: Any, **kwargs: Any) -> Any:
        return True


def build(**overrides: Any) -> FastAPI:
    app = FastAPI()
    kwargs: dict[str, Any] = {
        "service_name": "test-service",
        "environment": "test",
        "cors": {"allow_origins": ["http://localhost:3000"]},
        "hmac_secret": SECRET,
        "hmac_skip_paths": ["/api/v1/health"],
        "hmac_redis_client": _FakeRedis(),
    }
    kwargs.update(overrides)
    install_standard_middleware(app, **kwargs)
    return app


def order(app: FastAPI) -> list[str]:
    """Outermost first."""
    return [m.cls.__name__ for m in app.user_middleware]


def kwargs_for(app: FastAPI, name: str) -> dict[str, Any]:
    for m in app.user_middleware:
        if m.cls.__name__ == name:
            return dict(m.kwargs)
    raise AssertionError(f"{name} not installed")


CANONICAL = [
    "CORSMiddleware",
    "GlobalErrorHandlerMiddleware",
    "CorrelationIDMiddleware",
    "LoggingMiddleware",
    "GatewayHMACMiddleware",
    "IdentityExtractionMiddleware",
]


def test_canonical_order_with_every_optional_layer_enabled():
    app = build(
        rate_limit=("limiter", "config"),
        idempotency_redis_url="redis://localhost:6379/0",
    )
    assert order(app) == [
        "CORSMiddleware",
        "GlobalErrorHandlerMiddleware",
        "CorrelationIDMiddleware",
        "LoggingMiddleware",
        "RateLimitMiddleware",
        "GatewayHMACMiddleware",
        "IdentityExtractionMiddleware",
        "APIIdempotencyMiddleware",
    ]


def test_minimal_stack_is_the_canonical_six():
    assert order(build()) == CANONICAL


@pytest.mark.parametrize(
    "override,absent",
    [
        ({"cors": None}, "CORSMiddleware"),
        ({"rate_limit": None}, "RateLimitMiddleware"),
        ({"idempotency_redis_url": None}, "APIIdempotencyMiddleware"),
    ],
)
def test_each_optional_layer_omits_only_itself(override, absent):
    installed = order(build(**override))
    assert absent not in installed
    assert [m for m in CANONICAL if m != absent] == [
        m for m in installed if m in CANONICAL
    ]


def test_hmac_is_always_outside_identity():
    """The strongest constraint in the stack, and the one nothing else enforces.

    IdentityExtractionMiddleware's own docstring says it "Runs AFTER
    GatewayHMACMiddleware — headers are trusted by this point." But it only
    reads `request.headers`, and HMAC sets no state, so nothing at runtime
    couples them. Reverse the two and every service trusts unverified
    `X-User-*` headers, silently, with no test failing anywhere else.
    """
    for app in (
        build(),
        build(rate_limit=("l", "c")),
        build(extras=[(Slot.INNERMOST, _Marker, {})]),
        build(extras=[(Slot.BEFORE_HMAC, _Marker, {})]),
    ):
        names = order(app)
        assert names.index("GatewayHMACMiddleware") < names.index(
            "IdentityExtractionMiddleware"
        )


def test_cors_is_outside_the_error_handler():
    """An error response must still carry CORS headers, or the browser reports
    a CORS failure and the real 500 never reaches the developer."""
    names = order(build())
    assert names.index("CORSMiddleware") < names.index(
        "GlobalErrorHandlerMiddleware"
    )


def test_idempotency_is_inside_hmac():
    """tr-lead-management ran APIIdempotencyMiddleware OUTSIDE HMAC, which made
    it a denial-of-service primitive rather than a correctness aid.

    The middleware claims the Redis key with SET NX *before* calling downstream,
    and caches every response under 500 — 4xx included — for 24 hours. So an
    unauthenticated POST carrying a guessed Idempotency-Key claimed the key, was
    rejected 403 by HMAC, and the 403 was cached; the legitimate signed request
    with that key was then served the cached 403 for a day and never reached the
    route. Inside HMAC, an unsigned request is rejected before a key is claimed.
    """
    names = order(build(idempotency_redis_url="redis://localhost:6379/0"))
    assert names.index("GatewayHMACMiddleware") < names.index(
        "APIIdempotencyMiddleware"
    )


def test_hmac_redis_client_is_required():
    """Omitting it must be a TypeError, not a silent deployment with replay
    protection off. Two services shipped without one for exactly that reason."""
    app = FastAPI()
    with pytest.raises(TypeError):
        install_standard_middleware(  # type: ignore[call-arg]
            app,
            service_name="s",
            environment="test",
            cors=None,
            hmac_secret=SECRET,
            hmac_skip_paths=[],
        )


@pytest.mark.parametrize(
    "slot,expected_neighbour,side",
    [
        (Slot.OUTERMOST, "CORSMiddleware", "outside"),
        (Slot.BEFORE_HMAC, "GatewayHMACMiddleware", "outside"),
        (Slot.INNERMOST, "IdentityExtractionMiddleware", "inside"),
    ],
)
def test_each_slot_lands_where_it_claims(slot, expected_neighbour, side):
    names = order(build(extras=[(slot, _Marker, {})]))
    marker, neighbour = names.index("_Marker"), names.index(expected_neighbour)
    if side == "outside":
        assert marker < neighbour
    else:
        assert marker > neighbour


def test_before_hmac_extra_is_inside_logging():
    """S2SAuthMiddleware (realty-hub) sits here so its 401s are logged and carry
    a correlation id. Outside Logging they would be invisible."""
    names = order(build(extras=[(Slot.BEFORE_HMAC, _Marker, {})]))
    assert names.index("LoggingMiddleware") < names.index("_Marker")


def test_outermost_extra_is_outside_cors():
    """SecurityHeadersMiddleware (lead-management) must see EVERY response,
    including preflights and short-circuited 4xx, or those lose CSP."""
    names = order(build(extras=[(Slot.OUTERMOST, _Marker, {})]))
    assert names.index("_Marker") < names.index("CORSMiddleware")


def test_extras_within_one_slot_keep_the_order_given():
    names = order(
        build(
            extras=[
                (Slot.OUTERMOST, _Marker, {}),
                (Slot.OUTERMOST, _OtherMarker, {}),
            ]
        )
    )
    assert names.index("_Marker") < names.index("_OtherMarker")


def test_extra_kwargs_reach_the_middleware():
    app = build(extras=[(Slot.INNERMOST, _Marker, {"flag": 7})])
    assert kwargs_for(app, "_Marker") == {"flag": 7}


def test_logging_always_receives_the_service_name():
    """LoggingMiddleware defaults service_name to "unknown". Two services never
    passed it, so their logs were attributed to nobody. The factory makes the
    argument non-optional at the call site."""
    assert kwargs_for(build(), "LoggingMiddleware")["service_name"] == (
        "test-service"
    )


def test_slack_webhook_none_is_coerced_to_empty_string():
    """Callers pass `settings.SLACK_ERROR_WEBHOOK_URL`, which is None on some
    services. GlobalErrorHandlerMiddleware wants a str."""
    app = build(slack_webhook_url=None)
    assert kwargs_for(app, "GlobalErrorHandlerMiddleware")["slack_webhook_url"] == ""


def test_hmac_tolerance_default_is_left_to_the_library():
    """None must mean "the library's default", not "0 seconds"."""
    assert "tolerance_seconds" not in kwargs_for(build(), "GatewayHMACMiddleware")


def test_hmac_tolerance_is_forwarded_when_given():
    app = build(hmac_tolerance_seconds=45)
    assert kwargs_for(app, "GatewayHMACMiddleware")["tolerance_seconds"] == 45


def test_skip_paths_accepts_a_set():
    """tr-realty-data-hub declares its skip list as a set."""
    app = build(hmac_skip_paths={"/api/v1/health", "/docs"})
    passed = kwargs_for(app, "GatewayHMACMiddleware")["skip_paths"]
    assert isinstance(passed, list)
    assert set(passed) == {"/api/v1/health", "/docs"}
