"""Drive a service's real auth chain from a test, without bypassing any of it.

``AUTH_LIB_DEV_MODE_BYPASS`` is not permitted in tests. It short-circuits
``GatewayHMACMiddleware`` *and* ``require_auth``, so a suite running under it can
never catch an HMAC, identity-extraction or tenant-resolution regression — the
three things most likely to break when the gateway contract moves.

What a test actually needs is narrower: every real layer runs, except the HTTP
call to a service that is not running. So ``signed_client`` does two things:

1. **Signs like the gateway**, using the library's own ``compute_signature`` —
   so these tests break if the ``SignedHeader`` contract and the verifier ever
   disagree, which is the point.
2. **Substitutes the AuthContext provider** via
   ``app.dependency_overrides[get_auth_context_client]``. ``require_auth``
   resolves the provider through that dependency, so HMAC verification, identity
   extraction and every check inside ``require_auth`` still execute.

This lives in shared-auth-lib rather than tr-shared-lib deliberately. It is auth
code: it depends on ``compute_signature``, ``SignedHeader`` and
``AuthContextProvider``, all of which are owned here. tr-shared-lib is the base
library that shared-auth-lib itself depends on, so putting a helper there that
imports ``shared_auth_lib`` would invert the layering and leave the helper
untestable in the repository that owns its contract.

Two details that are easy to get wrong, and were wrong in the fleet:

* **Sign at send time, over the request's real headers.** One service pre-built a
  4-key header dict, signed that, then merged caller headers *over* the signed
  ones — so a test passing its own ``X-Tenant-ID`` signed one value and sent
  another, and got a 403 that looked like a library bug.
* **Override, do not register.** Every downstream service calls
  ``init_auth_context_client(AuthContextClient(...))`` inside its lifespan, and
  at least one test harness enters the real lifespan. A provider registered
  before the app starts is overwritten; a dependency override is not.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:  # pragma: no cover - typing only
    import httpx

__all__ = [
    "FakeAuthContextProvider",
    "Persona",
    "async_signed_client",
    "gateway_auth",
    "signed_client",
]


@dataclass(frozen=True)
class Persona:
    """Who a signed request claims to be.

    Vary *this* to test authorization, never the middleware. Subtracting a
    permission from a persona exercises the real ``require_permission`` path;
    disabling the auth chain proves nothing.
    """

    tenant_id: UUID = field(default_factory=uuid4)
    user_id: UUID = field(default_factory=uuid4)
    external_auth_id: UUID = field(default_factory=uuid4)
    email: str = "test-user@example.com"
    roles: tuple[str, ...] = ("admin",)
    permissions: tuple[str, ...] = ()
    site_id: UUID | None = None
    is_active: bool = True
    is_suspended: bool = False
    correlation_id: str | None = None

    def without(self, permission: str) -> Persona:
        """The same persona minus one permission — the 403 case, precisely.

        Replaces the ``X-Dev-Permissions`` header trick, which only worked with
        the bypass enabled. Same expressiveness, and now the signature and
        identity layers run too.
        """
        return replace_permissions(
            self, tuple(p for p in self.permissions if p != permission)
        )

    def with_permissions(self, *permissions: str) -> Persona:
        return replace_permissions(self, tuple(permissions))

    def headers(self) -> dict[str, str]:
        """The identity headers the gateway would emit for this persona."""
        from tr_shared.contracts.headers import HttpHeader

        headers = {
            HttpHeader.USER_ID.value: str(self.external_auth_id),
            HttpHeader.USER_ROLE.value: self.roles[0] if self.roles else "",
            HttpHeader.TENANT_ID.value: str(self.tenant_id),
            HttpHeader.USER_EMAIL.value: self.email,
            HttpHeader.USER_PERMISSIONS.value: ",".join(self.permissions),
            HttpHeader.CORRELATION_ID.value: self.correlation_id or str(uuid4()),
        }
        if self.site_id is not None:
            headers[HttpHeader.SITE_ID.value] = str(self.site_id)
        return headers


def replace_permissions(persona: Persona, permissions: tuple[str, ...]) -> Persona:
    from dataclasses import replace

    return replace(persona, permissions=permissions)


class FakeAuthContextProvider:
    """Resolves AuthContext in-process instead of over HTTP to tr-crm-core.

    This is the *only* layer a test is allowed to replace, and it is replaced
    because the thing it talks to genuinely is not running: every service except
    crm-core constructs ``AuthContextClient("http://tr-crm-core:8000")``.

    Satisfies ``shared_auth_lib.dependencies.auth_dependencies.AuthContextProvider``
    structurally — the first parameter is positional-only there, so the name is
    free but the position is not.
    """

    def __init__(self, persona: Persona) -> None:
        self.persona = persona
        self.calls: list[UUID] = []

    async def get_auth_context(
        self, external_auth_id: UUID, /, correlation_id: str | None = None
    ) -> Any:
        from shared_auth_lib.models.auth_context import AuthContext

        self.calls.append(external_auth_id)
        persona = self.persona
        return AuthContext(
            external_auth_id=external_auth_id,
            user_id=persona.user_id,
            email=persona.email,
            tenant_id=persona.tenant_id,
            roles=list(persona.roles),
            permissions=list(persona.permissions),
            is_active=persona.is_active,
            is_suspended=persona.is_suspended,
            correlation_id=correlation_id or persona.correlation_id,
        )


def gateway_auth(secret: str | None = None) -> httpx.Auth:
    """An ``httpx.Auth`` that signs each request the way the gateway signs it.

    Signing happens in ``auth_flow``, i.e. after the caller's headers are on the
    request, so what is signed is always what is sent.
    """
    import httpx
    from shared_auth_lib.services.hmac_verifier import compute_signature
    from tr_shared.contracts.headers import HttpHeader

    candidate = secret or os.environ.get("AUTH_LIB_GATEWAY_SIGNING_SECRET")
    if not candidate:
        raise RuntimeError(
            "AUTH_LIB_GATEWAY_SIGNING_SECRET is unset, so requests cannot be signed. "
            "Set it in the service's test settings — do not enable "
            "AUTH_LIB_DEV_MODE_BYPASS to work around this."
        )
    resolved: str = candidate

    class _GatewaySigner(httpx.Auth):
        def auth_flow(self, request: httpx.Request) -> Any:
            timestamp = datetime.now(UTC).isoformat()
            request.headers[HttpHeader.GATEWAY_TIMESTAMP.value] = timestamp
            request.headers[HttpHeader.GATEWAY_SIGNATURE.value] = compute_signature(
                method=request.method,
                path=request.url.path,
                headers=dict(request.headers),
                secret=resolved,
                timestamp=timestamp,
            )
            yield request

    return _GatewaySigner()


def signed_client(
    app: Any,
    persona: Persona | None = None,
    *,
    secret: str | None = None,
    **client_kwargs: Any,
) -> Any:
    """A ``TestClient`` that passes the real auth chain as ``persona``.

    Returns a client with ``.persona`` and ``.auth_provider`` attached, so a test
    can assert on what the provider was asked for.

    The caller owns teardown of ``app.dependency_overrides`` only if it installed
    others; this function removes just the one key it added, on ``close()``.
    """
    from fastapi.testclient import TestClient
    from shared_auth_lib.dependencies.auth_dependencies import (
        get_auth_context_client,
    )

    resolved_persona = persona or Persona()
    provider = FakeAuthContextProvider(resolved_persona)
    # Fail before mutating the app if the secret is missing, so a misconfigured
    # test cannot leave an override behind.
    auth = gateway_auth(secret)

    class _SignedTestClient(TestClient):
        """Removes its own dependency override when it goes out of scope.

        Both exits are overridden on purpose. Starlette's ``TestClient.__exit__``
        closes its portal and never calls ``close()``, so patching ``close``
        alone leaves the override installed after a ``with`` block — and a leaked
        override silently authenticates the next test's app.
        """

        def _remove_override(self) -> None:
            if app.dependency_overrides.get(get_auth_context_client) is _provide:
                del app.dependency_overrides[get_auth_context_client]

        def __exit__(self, *exc_info: Any) -> None:
            try:
                super().__exit__(*exc_info)
            finally:
                self._remove_override()

        def close(self) -> None:
            try:
                super().close()
            finally:
                self._remove_override()

    def _provide() -> FakeAuthContextProvider:
        return provider

    app.dependency_overrides[get_auth_context_client] = _provide

    client = _SignedTestClient(app, **client_kwargs)
    client.auth = auth
    client.headers.update(resolved_persona.headers())
    client.persona = resolved_persona  # type: ignore[attr-defined]
    client.auth_provider = provider  # type: ignore[attr-defined]
    return client


def async_signed_client(
    app: Any,
    persona: Persona | None = None,
    *,
    secret: str | None = None,
    **client_kwargs: Any,
) -> Any:
    """The ``signed_client`` contract over an ASGI transport, for async test suites.

    ``signed_client`` wraps FastAPI's synchronous ``TestClient``; several
    services drive their app through ``httpx.AsyncClient(transport=ASGITransport)``
    instead and cannot use it as-is. Same persona, same gateway_auth signer, same
    dependency-override seam — only the transport differs.
    """
    from httpx import ASGITransport, AsyncClient
    from shared_auth_lib.dependencies.auth_dependencies import (
        get_auth_context_client,
    )

    resolved_persona = persona or Persona()
    provider = FakeAuthContextProvider(resolved_persona)
    auth = gateway_auth(secret)

    class _AsyncSignedClient(AsyncClient):
        """Removes its own dependency override when it goes out of scope.

        Both exits are overridden on purpose, and neither can be dropped.
        Unlike Starlette's ``TestClient.__exit__`` (which never calls ``close()``),
        httpx's ``AsyncClient.__aexit__`` never calls ``aclose()`` either — it
        tears down the transport directly. So a caller using ``async with`` hits
        only ``__aexit__``, and a caller calling ``aclose()`` directly never
        reaches ``__aexit__``. Both must remove the override or one usage leaks it.
        """

        def _remove_override(self) -> None:
            if app.dependency_overrides.get(get_auth_context_client) is _provide:
                del app.dependency_overrides[get_auth_context_client]

        async def aclose(self) -> None:
            try:
                await super().aclose()
            finally:
                self._remove_override()

        async def __aexit__(self, *exc_info: Any) -> None:
            try:
                await super().__aexit__(*exc_info)
            finally:
                self._remove_override()

    def _provide() -> FakeAuthContextProvider:
        return provider

    app.dependency_overrides[get_auth_context_client] = _provide

    client = _AsyncSignedClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        auth=auth,
        headers=resolved_persona.headers(),
        **client_kwargs,
    )
    client.persona = resolved_persona  # type: ignore[attr-defined]
    client.auth_provider = provider  # type: ignore[attr-defined]
    return client
