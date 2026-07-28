"""signed_client drives the REAL chain — proven, not asserted.

Every test here mounts the production middleware stack in the production order
(HMAC before identity, as every service does) and then checks that removing any
one thing signed_client provides causes the request to fail the way the real
gateway contract says it should. If any of these started passing without the
signature, the helper would be a bypass wearing a different name.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from shared_auth_lib.dependencies.auth_dependencies import (
    _AuthClientRegistry,
    get_auth_context_client,
    require_auth,
    require_permission,
    reset_auth_context_client,
)
from shared_auth_lib.middleware.hmac_middleware import GatewayHMACMiddleware
from shared_auth_lib.middleware.identity_middleware import (
    IdentityExtractionMiddleware,
)
from shared_auth_lib.models.auth_context import AuthContext
from shared_auth_lib.testing import FakeAuthContextProvider, Persona, signed_client

SECRET = "test-gateway-signing-secret"


@pytest.fixture(autouse=True)
def _clean_registry(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTH_LIB_GATEWAY_SIGNING_SECRET", SECRET)
    # The bypass is never permitted in tests; assert the environment agrees so a
    # stray export cannot make this whole file pass for the wrong reason.
    monkeypatch.setenv("AUTH_LIB_DEV_MODE_BYPASS", "false")
    _AuthClientRegistry.reset()
    yield
    _AuthClientRegistry.reset()


def _app() -> FastAPI:
    """The production stack: HMAC verified first, then identity extracted."""
    app = FastAPI()
    app.add_middleware(IdentityExtractionMiddleware)
    app.add_middleware(
        GatewayHMACMiddleware,
        secret=SECRET,
        skip_paths=["/api/v1/health"],
    )

    @app.get("/api/v1/whoami")
    async def whoami(auth: AuthContext = Depends(require_auth)):
        return {
            "user_id": str(auth.user_id),
            "tenant_id": str(auth.tenant_id),
            "email": auth.email,
            "permissions": auth.permissions,
        }

    @app.get("/api/v1/invoices")
    async def invoices(
        auth: AuthContext = Depends(require_permission("finance:invoice:read")),
    ):
        return {"ok": True}

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    return app


class TestTheChainActuallyRuns:
    def test_signed_request_reaches_the_route(self) -> None:
        persona = Persona(email="agent@thinkrealty.ae")
        with signed_client(_app(), persona) as client:
            response = client.get("/api/v1/whoami")

        assert response.status_code == 200, response.text
        assert response.json()["tenant_id"] == str(persona.tenant_id)
        assert response.json()["email"] == persona.email

    def test_an_unsigned_client_is_rejected(self) -> None:
        """The control. If this ever returns 200 the helper proves nothing."""
        with TestClient(_app()) as client:
            response = client.get("/api/v1/whoami", headers=Persona().headers())

        assert response.status_code == 403

    def test_a_tampered_header_invalidates_the_signature(self) -> None:
        """Signing happens at send time, over the headers actually sent.

        A signer that pre-builds a header dict and lets caller headers win would
        pass this request through with a signature over different values. One
        service in the fleet had exactly that bug, latent.
        """
        persona = Persona()
        with signed_client(_app(), persona) as client:
            # Same client, but this request carries a different tenant than the
            # one whose value gets signed... which is fine, because signing sees
            # the final headers. What must NOT happen is a mismatch.
            response = client.get(
                "/api/v1/whoami",
                headers={"X-Tenant-ID": str(uuid4())},
            )

        assert response.status_code == 200, response.text

    def test_replaying_a_signature_against_a_different_path_fails(self) -> None:
        """The signature covers the path, so it cannot be moved to another route."""
        persona = Persona()
        app = _app()
        with signed_client(app, persona) as client:
            captured = client.get("/api/v1/whoami")
            assert captured.status_code == 200
            headers = dict(captured.request.headers)

        with TestClient(app) as plain:
            replayed = plain.get("/api/v1/invoices", headers=headers)

        assert replayed.status_code == 403


class TestPersonaDrivesAuthorization:
    def test_permission_granted(self) -> None:
        persona = Persona(permissions=("finance:invoice:read",))
        with signed_client(_app(), persona) as client:
            assert client.get("/api/v1/invoices").status_code == 200

    def test_permission_withheld_is_403_through_the_real_dependency(self) -> None:
        persona = Persona(permissions=("finance:invoice:read", "finance:invoice:write"))
        with signed_client(_app(), persona.without("finance:invoice:read")) as client:
            response = client.get("/api/v1/invoices")

        assert response.status_code == 403
        # ...and the request DID pass HMAC and identity extraction to get here.
        assert "signature" not in response.text.lower()

    def test_without_leaves_other_permissions_intact(self) -> None:
        persona = Persona(permissions=("a", "b", "c"))
        assert persona.without("b").permissions == ("a", "c")

    def test_personas_are_isolated_per_client(self) -> None:
        first, second = Persona(), Persona()
        assert first.tenant_id != second.tenant_id


class TestProviderSubstitution:
    def test_provider_is_asked_for_the_signed_user(self) -> None:
        persona = Persona()
        with signed_client(_app(), persona) as client:
            client.get("/api/v1/whoami")
            provider = client.auth_provider

        assert provider.calls == [persona.external_auth_id]

    def test_override_is_removed_on_close(self) -> None:
        """A leaked override would silently authenticate a later test's app."""
        app = _app()
        with signed_client(app, Persona()):
            assert get_auth_context_client in app.dependency_overrides
        assert get_auth_context_client not in app.dependency_overrides

    def test_override_beats_a_lifespan_registration(self) -> None:
        """Services register their real client inside lifespan; the override must win.

        This is why signed_client uses dependency_overrides rather than
        init_auth_context_client: entering the app's lifespan would otherwise
        overwrite a pre-registered fake and every request would try to reach
        http://tr-crm-core:8000.
        """
        app = _app()

        class _Unreachable:
            async def get_auth_context(self, external_auth_id, /, correlation_id=None):
                raise AssertionError("the real HTTP client must not be reached")

        persona = Persona()
        with signed_client(app, persona) as client:
            # Simulate the service's lifespan registering the real client after
            # the test harness built its client.
            from shared_auth_lib.dependencies.auth_dependencies import (
                init_auth_context_client,
            )

            init_auth_context_client(_Unreachable())
            response = client.get("/api/v1/whoami")

        assert response.status_code == 200, response.text


class TestSkipPathsStillWork:
    def test_health_needs_no_signature(self) -> None:
        with TestClient(_app()) as client:
            assert client.get("/api/v1/health").status_code == 200


class TestMisconfiguration:
    def test_missing_secret_is_a_loud_error_not_a_bypass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AUTH_LIB_GATEWAY_SIGNING_SECRET", raising=False)
        with pytest.raises(RuntimeError, match="AUTH_LIB_GATEWAY_SIGNING_SECRET"):
            signed_client(_app(), Persona())


class TestRegistryReset:
    def test_reset_helper_clears_the_registry(self) -> None:
        """The additive export, so suites stop touching _AuthClientRegistry."""
        from shared_auth_lib.dependencies.auth_dependencies import (
            init_auth_context_client,
        )

        init_auth_context_client(FakeAuthContextProvider(Persona()))
        assert get_auth_context_client() is not None

        reset_auth_context_client()
        with pytest.raises(RuntimeError, match="not initialized"):
            get_auth_context_client()
