"""Runs AFTER GatewayHMACMiddleware — headers are trusted by this point."""

from uuid import UUID

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from tr_shared.contracts.headers import HttpHeader

from shared_auth_lib.exceptions import InvalidIdentityHeaderError
from shared_auth_lib.logging import get_logger
from shared_auth_lib.models.auth_context import GatewayIdentityHeaders

logger = get_logger(__name__)


class IdentityExtractionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            identity = self._extract_identity(request)
            request.state.identity = identity
        except InvalidIdentityHeaderError as exc:
            logger.warning(
                "invalid_identity_header",
                extra={
                    "error": str(exc),
                    "path": request.url.path,
                },
            )
            request.state.identity = GatewayIdentityHeaders()

        return await call_next(request)

    def _extract_identity(self, request: Request) -> GatewayIdentityHeaders:
        headers = request.headers

        user_id_str = headers.get(HttpHeader.USER_ID.value)
        user_id: UUID | None = None
        if user_id_str:
            try:
                user_id = UUID(user_id_str)
            except ValueError as exc:
                raise InvalidIdentityHeaderError(
                    f"{HttpHeader.USER_ID.value} must be a valid UUID, got: "
                    f"{user_id_str}"
                ) from exc

        tenant_id_str = headers.get(HttpHeader.TENANT_ID.value)
        tenant_id: UUID | None = None
        if tenant_id_str:
            try:
                tenant_id = UUID(tenant_id_str)
            except ValueError as exc:
                raise InvalidIdentityHeaderError(
                    f"{HttpHeader.TENANT_ID.value} must be a valid UUID, got: "
                    f"{tenant_id_str}"
                ) from exc

        permissions_raw = headers.get(HttpHeader.USER_PERMISSIONS.value) or ""
        permissions = [p for p in permissions_raw.split(",") if p]

        return GatewayIdentityHeaders(
            user_id=user_id,
            user_role=headers.get(HttpHeader.USER_ROLE.value),
            tenant_id=tenant_id,
            # Email and permissions are HMAC-signed (SIGNED_HEADERS) — safe to trust.
            user_email=headers.get(HttpHeader.USER_EMAIL.value),
            permissions=permissions,
            auth_provider=headers.get(HttpHeader.AUTH_PROVIDER.value, "supabase"),
            correlation_id=(
                headers.get(HttpHeader.CORRELATION_ID.value)
                or getattr(request.state, "correlation_id", None)
            ),
            gateway_signature=headers.get(HttpHeader.GATEWAY_SIGNATURE.value),
            gateway_timestamp=headers.get(HttpHeader.GATEWAY_TIMESTAMP.value),
        )


def get_gateway_identity(
    request: Request,
) -> GatewayIdentityHeaders:
    return getattr(request.state, "identity", GatewayIdentityHeaders())
