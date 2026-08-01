from typing import Any

from fastapi import status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from tr_shared.contracts.headers import HttpHeader
from tr_shared.schemas import build_error_envelope

from shared_auth_lib.logging import get_logger
from shared_auth_lib.services.hmac_verifier import verify_signature

logger = get_logger(__name__)


def _rejected(request: Request, message: str, code: str) -> JSONResponse:
    """A 403 in the canonical envelope.

    Middleware runs outside the exception-handler chain, so it cannot raise a
    typed exception and must build the body itself — but it must build the same
    body. Hand-rolled dicts here are how three HMAC rejections came to omit
    ``correlation_id`` and carry unprefixed codes.
    """
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content=build_error_envelope(
            message=message,
            code=code,
            correlation_id=request.headers.get(HttpHeader.CORRELATION_ID.value),
        ),
    )

DEFAULT_SKIP_PATHS: list[str] = [
    "/api/v1/health",
    "/health",
    "/docs",
    "/openapi.json",
    "/api/v1/internal/",
    "/internal/",
]


def path_is_skipped(path: str, skip_paths: list[str]) -> bool:
    """Whether *path* is exempt from HMAC verification under *skip_paths*.

    The skip_paths mini-language:

    - Trailing ``/`` — prefix match. ``/internal/`` covers ``/internal/x`` and
      bare ``/internal``, but not ``/internalize``.
    - No trailing ``/`` — exact match. ``/api/v1/health`` does not cover
      ``/api/v1/health/ready``.
    - ``"/"`` — the root route only. It ends in a slash but prefixes every
      path, so prefix-matching it would exempt the entire service.

    Single source of truth: the middleware and every OpenAPI schema builder
    that marks routes public must call this rather than reimplement it.
    """
    for skip in skip_paths:
        if skip == "/":
            if path == "/":
                return True
        elif skip.endswith("/"):
            if path.startswith(skip) or path == skip.rstrip("/"):
                return True
        elif path == skip:
            return True
    return False


class GatewayHMACMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        secret: str,
        skip_paths: list[str] | None = None,
        tolerance_seconds: int = 30,
        dev_mode_bypass: bool | None = None,
        redis_client: Any | None = None,
        replay_protection_fail_open: bool = True,
    ) -> None:
        super().__init__(app)
        self.secret = secret
        self.skip_paths = (
            skip_paths if skip_paths is not None else DEFAULT_SKIP_PATHS
        )
        self.tolerance_seconds = tolerance_seconds
        self._redis = redis_client
        self._replay_fail_open = replay_protection_fail_open
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
        self._hmac_failure_replay: int = 0

    @property
    def hmac_stats(self) -> dict:
        total = (
            self._hmac_success
            + self._hmac_failure_missing
            + self._hmac_failure_invalid
            + self._hmac_failure_replay
        )
        failure_rate = 0.0
        if total > 0:
            failures = (
                self._hmac_failure_missing
                + self._hmac_failure_invalid
                + self._hmac_failure_replay
            )
            failure_rate = (failures / total) * 100
        return {
            "success": self._hmac_success,
            "failure_missing_headers": self._hmac_failure_missing,
            "failure_invalid_signature": self._hmac_failure_invalid,
            "failure_replay": self._hmac_failure_replay,
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
            # Identity injected downstream via require_auth — Starlette's
            # BaseHTTPMiddleware doesn't propagate scope/state mutations here.
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
            return _rejected(
                request,
                "Missing gateway signature headers",
                "AUTHLIB_AUTH_008",
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
            return _rejected(
                request,
                "Invalid gateway signature",
                "AUTHLIB_AUTH_009",
            )

        if self._redis is not None and await self._is_replay(
            signature, path, request
        ):
            self._hmac_failure_replay += 1
            logger.warning(
                "replayed_gateway_signature",
                extra={
                    "path": path,
                    "correlation_id": request.headers.get(
                        HttpHeader.CORRELATION_ID.value
                    ),
                    "metric_type": "hmac_verification",
                    "result": "failure_replay",
                },
            )
            return _rejected(
                request,
                "Replayed gateway signature",
                "AUTHLIB_AUTH_010",
            )

        self._hmac_success += 1
        return await call_next(request)

    async def _is_replay(self, signature: str, path: str, request: Request) -> bool:
        # dispatch() only calls _is_replay when self._redis is not None.
        assert self._redis is not None
        key = f"hmac_sig:{signature}"
        try:
            stored = await self._redis.set(
                key, "1", nx=True, ex=self.tolerance_seconds
            )
            # redis-py SET NX: True = first sighting, None = already present (replay).
            return not bool(stored)
        except Exception as exc:
            logger.warning(
                "hmac_replay_check_failed",
                extra={
                    "path": path,
                    "error": str(exc),
                    "correlation_id": request.headers.get(
                        HttpHeader.CORRELATION_ID.value
                    ),
                    "fail_open": self._replay_fail_open,
                },
            )
            return not self._replay_fail_open

    def _should_skip(self, path: str) -> bool:
        return path_is_skipped(path, self.skip_paths)
