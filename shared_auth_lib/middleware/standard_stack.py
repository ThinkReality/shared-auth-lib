"""One assembly order for the fleet's request stack.

**The Starlette rule.** `app.add_middleware` INSERTS AT POSITION 0. The last
call therefore produces the OUTERMOST layer, and `app.user_middleware[0]` is
what sees a request first. tr-media-service's `main.py` carried the comment
"First added = outermost" — the exact reverse — and its whole stack ran inside
out for months: every browser preflight to a guarded path 403'd with no CORS
headers, and every HMAC rejection came back with no correlation id and no Slack
alert, because CorrelationID and the error handler sat *inside* the thing
rejecting the request. Nothing failed in dev, because dev compose sets
`AUTH_LIB_DEV_MODE_BYPASS=true`. Nothing failed in CI either: not one test in
the fleet asserted the order.

This module exists so that order is written once, verified once, and cannot be
re-derived by hand at seven call sites.

**Canonical order, outermost → innermost:**

    extras[OUTERMOST] → CORS → GlobalErrorHandler → CorrelationID → Logging
      → extras[BEFORE_HMAC] → RateLimit → GatewayHMAC → Identity
      → Idempotency → extras[INNERMOST]

Why each boundary is where it is:

* **CORS outside the error handler** — an error response must still carry CORS
  headers, or the browser reports a CORS failure and the developer never sees
  the real 500.
* **CorrelationID and Logging outside HMAC** — a rejected request is exactly the
  one you need to trace. Inside, HMAC's 403s are invisible.
* **HMAC outside Identity** — `IdentityExtractionMiddleware` reads `X-User-*`
  and its docstring says "headers are trusted by this point". It reads only
  `request.headers`, and HMAC sets no state, so nothing at runtime enforces the
  pairing. Reverse them and the service trusts unverified identity headers,
  silently. This is the single most important line in this file.
* **Idempotency inside HMAC** — outside, it is a denial-of-service primitive:
  the key is claimed with SET NX before the request is authenticated, and 4xx
  responses are cached for 24h, so an unsigned request with a guessed key can
  poison it for a day. tr-lead-management shipped it outside.

**`setup_monitoring` must be called BEFORE this function.** It installs
`MetricsMiddleware`, and calling it first puts metrics innermost, so the
histogram measures route handling rather than the whole stack. Call it after and
metrics wraps everything — which is what tr-realty-data-hub did.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Any

from starlette.middleware.cors import CORSMiddleware
from tr_shared.middleware import (
    CorrelationIDMiddleware,
    GlobalErrorHandlerMiddleware,
    LoggingMiddleware,
)

from shared_auth_lib.middleware.hmac_middleware import GatewayHMACMiddleware
from shared_auth_lib.middleware.identity_middleware import (
    IdentityExtractionMiddleware,
)

__all__ = ["Slot", "install_standard_middleware"]


class Slot(StrEnum):
    """Where a service's own middleware may join the standard stack.

    Three slots, each justified by exactly one real service. Resist adding a
    fourth: a slot for every caller is the hand-rolled stack again, wearing a
    factory's name.
    """

    OUTERMOST = "outermost"
    """Outside CORS. For layers that must touch EVERY response, including
    preflights and short-circuited errors — `SecurityHeadersMiddleware`
    (tr-lead-management) would otherwise drop CSP on exactly those."""

    BEFORE_HMAC = "before_hmac"
    """Inside Logging, outside HMAC. For an auxiliary auth check that needs its
    own rejections logged and correlated — `S2SAuthMiddleware`
    (tr-realty-data-hub)."""

    INNERMOST = "innermost"
    """Inside Identity. For consumers of the identity it extracts —
    `AuditContextMiddleware` (tr-crm-core) reads `request.state.identity`."""


def install_standard_middleware(
    app: Any,
    *,
    service_name: str,
    environment: str,
    hmac_secret: str,
    hmac_skip_paths: Sequence[str],
    hmac_redis_client: Any,
    cors: dict[str, Any] | None,
    slack_webhook_url: str | None = "",
    hmac_tolerance_seconds: int | None = None,
    replay_protection_fail_open: bool | None = None,
    rate_limit: tuple[Any, Any] | None = None,
    idempotency_redis_url: str | None = None,
    extras: Sequence[tuple[Slot, type, dict[str, Any]]] = (),
) -> None:
    """Install the fleet-standard request stack on `app`.

    Call `setup_monitoring` first if the service uses it — see the module
    docstring.

    Args:
        service_name: Passed to Logging and the error handler. Not optional:
            `LoggingMiddleware` silently defaults it to "unknown", and two
            services shipped logs attributed to nobody because of it.
        environment: One of development / test / staging / production.
        hmac_secret: Shared secret with the gateway.
        hmac_skip_paths: Paths exempt from signature verification. Any sequence
            — tr-realty-data-hub declares a set — normalised to a list here.
        hmac_redis_client: REQUIRED, and typed `Any` on purpose:
            tr-whatsApp-marketing-agent passes a forwarding proxy that
            re-resolves `app.state.hmac_redis` on each lifespan cycle. Required
            rather than defaulted because a default of `None` silently disables
            replay protection, which is how two services shipped without it.
        cors: Kwargs for `CORSMiddleware`, or None to install no CORS layer
            (tr-whatsApp-marketing-agent, when `CORS_ORIGINS` is empty). A dict
            rather than discrete parameters because the seven services' CORS
            configs share no shape worth inventing.
        slack_webhook_url: None is coerced to "" — callers pass a settings
            value that is optional on several services.
        hmac_tolerance_seconds: None leaves the library default in force.
        replay_protection_fail_open: None leaves the library default in force.
            `False` makes a request fail CLOSED when the replay-protection
            Redis is unreachable, instead of being let through unchecked.
            Not forwarded when None so the default has exactly one
            declaration, on `GatewayHMACMiddleware.__init__`.
        rate_limit: `(limiter, config)`, or None for no rate limiting.
        idempotency_redis_url: Redis URL, or None for no idempotency layer.
        extras: `(slot, middleware_class, kwargs)`, applied in the order given
            within each slot.
    """
    by_slot: dict[Slot, list[tuple[type, dict[str, Any]]]] = {
        slot: [] for slot in Slot
    }
    for slot, cls, kwargs in extras:
        by_slot[Slot(slot)].append((cls, kwargs))

    def add(cls: type, **kwargs: Any) -> None:
        app.add_middleware(cls, **kwargs)

    def add_slot(slot: Slot) -> None:
        # Reversed, because each add_middleware call lands outside the previous
        # one — so emitting a slot's entries backwards preserves the order the
        # caller wrote them in.
        for cls, kwargs in reversed(by_slot[slot]):
            add(cls, **kwargs)

    # Installed innermost-first: every call below wraps the ones above it.
    add_slot(Slot.INNERMOST)

    if idempotency_redis_url is not None:
        from tr_shared.middleware import APIIdempotencyMiddleware

        add(
            APIIdempotencyMiddleware,
            redis_url=idempotency_redis_url,
            service_name=service_name,
        )

    add(IdentityExtractionMiddleware)

    hmac_kwargs: dict[str, Any] = {
        "secret": hmac_secret,
        "skip_paths": list(hmac_skip_paths),
        "redis_client": hmac_redis_client,
    }
    if hmac_tolerance_seconds is not None:
        hmac_kwargs["tolerance_seconds"] = hmac_tolerance_seconds
    if replay_protection_fail_open is not None:
        hmac_kwargs["replay_protection_fail_open"] = replay_protection_fail_open
    add(GatewayHMACMiddleware, **hmac_kwargs)

    if rate_limit is not None:
        from tr_shared.rate_limiter import RateLimitMiddleware

        limiter, config = rate_limit
        add(RateLimitMiddleware, limiter=limiter, config=config)

    add_slot(Slot.BEFORE_HMAC)

    add(LoggingMiddleware, service_name=service_name)
    add(CorrelationIDMiddleware)
    add(
        GlobalErrorHandlerMiddleware,
        service_name=service_name,
        environment=environment,
        slack_webhook_url=slack_webhook_url or "",
    )

    if cors is not None:
        add(CORSMiddleware, **cors)

    add_slot(Slot.OUTERMOST)
