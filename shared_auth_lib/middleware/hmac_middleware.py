from fastapi import status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from tr_shared.contracts.headers import HttpHeader

from shared_auth_lib.logging import get_logger
from shared_auth_lib.services.hmac_verifier import verify_signature

logger = get_logger(__name__)

DEFAULT_SKIP_PATHS: list[str] = [
    "/api/v1/health",
    "/health",
    "/docs",
    "/openapi.json",
    "/api/v1/internal/",
    "/internal/",
]


class GatewayHMACMiddleware(BaseHTTPMiddleware):

    def __init__(
        self,
        app: ASGIApp,
        secret: str,
        skip_paths: list[str] | None = None,
        tolerance_seconds: int = 30,
        dev_mode_bypass: bool | None = None,
    ) -> None:
        super().__init__(app)
        self.secret = secret
        self.skip_paths = (
            skip_paths if skip_paths is not None else DEFAULT_SKIP_PATHS
        )
        self.tolerance_seconds = tolerance_seconds
        if dev_mode_bypass is None:
            from shared_auth_lib.config import get_settings

            try:
                self._dev_mode_bypass = get_settings().DEV_MODE_BYPASS
            except Exception:
                self._dev_mode_bypass = False
        else:
            self._dev_mode_bypass = dev_mode_bypass
        if self._dev_mode_bypass:
            logger.warning(
                "DEV_MODE_BYPASS ACTIVE — HMAC verification is disabled. "
                "All requests will use a fake dev identity. "
                "NEVER enable this in staging or production.",
            )
        self._hmac_success: int = 0
        self._hmac_failure_missing: int = 0
        self._hmac_failure_invalid: int = 0

    @property
    def hmac_stats(self) -> dict:
        total = (
            self._hmac_success
            + self._hmac_failure_missing
            + self._hmac_failure_invalid
        )
        failure_rate = 0.0
        if total > 0:
            failures = self._hmac_failure_missing + self._hmac_failure_invalid
            failure_rate = (failures / total) * 100
        return {
            "success": self._hmac_success,
            "failure_missing_headers": self._hmac_failure_missing,
            "failure_invalid_signature": self._hmac_failure_invalid,
            "total": total,
            "failure_rate": round(failure_rate, 2),
        }

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        path = request.url.path

        if self._should_skip(path):
            return await call_next(request)

        if self._dev_mode_bypass:
            # Skip HMAC verification. Identity is injected downstream in
            # require_auth via build_dev_auth_context() — we can't inject
            # it here reliably because Starlette's BaseHTTPMiddleware
            # doesn't propagate scope/state mutations across boundaries.
            return await call_next(request)

        signature = request.headers.get(HttpHeader.GATEWAY_SIGNATURE.value)
        timestamp = request.headers.get(HttpHeader.GATEWAY_TIMESTAMP.value)

        if not signature or not timestamp:
            self._hmac_failure_missing += 1
            logger.warning(
                "missing_gateway_signature_headers",
                extra={
                    "path": path,
                    "correlation_id": request.headers.get(
                        HttpHeader.CORRELATION_ID.value
                    ),
                    "metric_type": "hmac_verification",
                    "result": "failure_missing_headers",
                },
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": {
                        "message": "Missing gateway signature headers",
                        "code": "HMAC_MISSING_HEADERS",
                    }
                },
            )

        headers_dict = dict(request.headers)
        is_valid = verify_signature(
            method=request.method,
            path=path,
            headers=headers_dict,
            secret=self.secret,
            signature=signature,
            timestamp=timestamp,
            tolerance_seconds=self.tolerance_seconds,
        )

        if not is_valid:
            self._hmac_failure_invalid += 1
            logger.warning(
                "invalid_gateway_signature",
                extra={
                    "path": path,
                    "correlation_id": request.headers.get(
                        HttpHeader.CORRELATION_ID.value
                    ),
                    "metric_type": "hmac_verification",
                    "result": "failure_invalid_signature",
                },
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": {
                        "message": "Invalid gateway signature",
                        "code": "HMAC_INVALID_SIGNATURE",
                    }
                },
            )

        self._hmac_success += 1
        return await call_next(request)

    def _should_skip(self, path: str) -> bool:
        """Check if the path should bypass HMAC verification.

        Paths ending with '/' are treated as prefix matches:
          "/internal/" matches "/internal/status" but NOT "/internalize"
        All other paths are treated as exact matches:
          "/health" matches "/health" but NOT "/healthz"
        """
        for skip in self.skip_paths:
            if skip.endswith("/"):
                if path.startswith(skip) or path == skip.rstrip("/"):
                    return True
            else:
                if path == skip:
                    return True
        return False
