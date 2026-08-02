"""Test helpers for driving a service's real auth chain.

Import surface::

    from shared_auth_lib.testing import Persona, signed_client

    client = signed_client(app, Persona(permissions=("finance:invoice:read",)))
    assert client.get("/api/v1/finance/invoices").status_code == 200
    assert client.get("/api/v1/finance/invoices", ...).status_code == 403  # persona.without(...)

Nothing here disables, patches or bypasses a middleware. The only substituted
component is the AuthContext provider, because the service it calls
(tr-crm-core) is genuinely not running in a test process. HMAC verification,
identity extraction and ``require_auth`` all execute for real.
"""

from shared_auth_lib.testing._gateway import (
    FakeAuthContextProvider,
    Persona,
    async_signed_client,
    gateway_auth,
    signed_client,
)
from shared_auth_lib.testing.route_surfaces import (
    FAMILIES,
    RouteExemption,
    SurfaceSpec,
    assert_route_surfaces,
    classify_route,
    route_surface_report,
)

__all__ = [
    "FakeAuthContextProvider",
    "Persona",
    "async_signed_client",
    "gateway_auth",
    "signed_client",
    "FAMILIES",
    "RouteExemption",
    "SurfaceSpec",
    "assert_route_surfaces",
    "classify_route",
    "route_surface_report",
]
