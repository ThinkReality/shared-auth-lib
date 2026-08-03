"""The field must survive every path that builds an AuthContext.

Two of the three paths construct AuthContext from a CLOSED kwarg list, so a
field with a list default silently arrives empty rather than failing loudly —
and an empty entitlement list is a 403 on every gated module.
"""

from uuid import uuid4

from tr_shared.contracts import ENTITLEMENT_MODULES

from shared_auth_lib.models.auth_context import AuthContext

ALL_MODULES = sorted(m.value for m in ENTITLEMENT_MODULES)


def test_auth_context_carries_enabled_modules():
    ctx = AuthContext(
        external_auth_id=uuid4(),
        user_id=uuid4(),
        email="a@b.com",
        tenant_id=uuid4(),
        enabled_modules=["listing", "cms"],
    )
    assert ctx.enabled_modules == ["listing", "cms"]


def test_enabled_modules_defaults_to_empty_not_none():
    """Fail-closed: an unknown entitlement grants nothing."""
    ctx = AuthContext(
        external_auth_id=uuid4(), user_id=uuid4(), email="a@b.com", tenant_id=uuid4()
    )
    assert ctx.enabled_modules == []


def test_dev_bypass_grants_every_module_by_default():
    from shared_auth_lib._dev_headers import build_dev_auth_context

    ctx = build_dev_auth_context(None)
    assert sorted(ctx.enabled_modules) == ALL_MODULES, (
        "the dev bypass must grant everything by default — dev is the only live "
        "environment, and an empty list here 403s every gated route in the fleet"
    )


def test_dev_bypass_honours_the_x_dev_modules_header():
    from starlette.datastructures import Headers

    from shared_auth_lib._dev_headers import build_dev_auth_context

    class _Req:
        headers = Headers({"x-dev-modules": "listing, cms"})

    ctx = build_dev_auth_context(_Req())
    assert ctx.enabled_modules == ["listing", "cms"]


def test_signed_test_client_persona_grants_every_module_by_default():
    from shared_auth_lib.testing._gateway import Persona

    persona = Persona()
    assert sorted(persona.enabled_modules) == ALL_MODULES, (
        "the signed test client is the integration lane's only caller — an empty "
        "list here turns every gated integration test red"
    )


async def test_the_fake_provider_copies_the_personas_modules_through():
    """The Persona field is inert unless the provider forwards it.

    FakeAuthContextProvider builds AuthContext from a CLOSED kwarg list. A field
    present on Persona but absent from that call arrives as [] — and this provider
    is what every signed_client in all five gated services resolves through, so
    the omission would red the whole fleet's integration lane at once.
    """
    from shared_auth_lib.testing._gateway import FakeAuthContextProvider, Persona

    persona = Persona(enabled_modules=("listing", "cms"))
    ctx = await FakeAuthContextProvider(persona).get_auth_context(uuid4())
    assert ctx.enabled_modules == ["listing", "cms"]
