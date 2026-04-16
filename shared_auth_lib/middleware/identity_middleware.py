"""Identity header extraction and validation middleware.

Runs AFTER GatewayHMACMiddleware so that headers are already trusted.
Extracts X-User-Id, X-User-Role, X-Tenant-ID, etc. from the request,
validates UUID format, and stores the result in request.state.identity.
"""

from uuid import UUID

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from shared_auth_lib.exceptions import InvalidIdentityHeaderError
from shared_auth_lib.logging import get_logger
from shared_auth_lib.models.auth_context import GatewayIdentityHeaders

logger = get_logger(__name__)


class IdentityExtractionMiddleware(BaseHTTPMiddleware):
    """Extract and validate identity headers forwarded by API Gateway.

    Stores a GatewayIdentityHeaders instance on request.state.identity.
    If extraction fails (e.g. malformed UUID), an empty identity object
    is stored and a warning is logged. Auth dependencies downstream will
    handle the missing identity appropriately.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # If an upstream middleware already set identity (e.g. DEV_MODE_BYPASS
        # in GatewayHMACMiddleware), preserve it.
        existing = getattr(request.state, "identity", None)
        if isinstance(existing, GatewayIdentityHeaders) and existing.user_id:
            return await call_next(request)

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

    def _extract_identity(
        self, request: Request
    ) -> GatewayIdentityHeaders:
        """Extract and validate identity headers from the request."""
        headers = request.headers

        user_id_str = headers.get("X-User-Id")
        user_id: UUID | None = None
        if user_id_str:
            try:
                user_id = UUID(user_id_str)
            except ValueError as exc:
                raise InvalidIdentityHeaderError(
                    f"X-User-Id must be a valid UUID, got: "
                    f"{user_id_str}"
                ) from exc

        # Starlette normalizes incoming headers to lowercase.
        tenant_id_str = headers.get("x-tenant-id")
        tenant_id: UUID | None = None
        if tenant_id_str:
            try:
                tenant_id = UUID(tenant_id_str)
            except ValueError as exc:
                raise InvalidIdentityHeaderError(
                    f"X-Tenant-ID must be a valid UUID, got: "
                    f"{tenant_id_str}"
                ) from exc

        return GatewayIdentityHeaders(
            user_id=user_id,
            user_role=headers.get("X-User-Role"),
            tenant_id=tenant_id,
            # X-User-Email intentionally NOT extracted here.
            # It is not in SIGNED_HEADERS and not set by the
            # gateway, so a client could inject any value.
            # The authoritative email comes from AuthContext
            # (fetched from CRM-backend).
            auth_provider=headers.get(
                "X-Auth-Provider", "supabase"
            ),
            correlation_id=(
                headers.get("X-Correlation-Id")
                or getattr(request.state, "correlation_id", None)
            ),
            gateway_signature=headers.get("X-Gateway-Signature"),
            gateway_timestamp=headers.get("X-Gateway-Timestamp"),
        )


def get_gateway_identity(
    request: Request,
) -> GatewayIdentityHeaders:
    """FastAPI dependency to retrieve the identity set by middleware."""
    return getattr(
        request.state, "identity", GatewayIdentityHeaders()
    )
