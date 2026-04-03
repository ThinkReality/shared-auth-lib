"""Client for fetching AuthContext from CRM-backend internal API.

Two-layer caching strategy:
  1. **In-memory process cache** (TTL 60s) — eliminates HTTP calls for
     repeat requests within the same service instance.  Auth is on the
     critical path of every request; sub-millisecond lookups matter.
  2. **CRM-backend Redis cache** (TTL 300s) — handled server-side by
     CRM's AuthContextCacheService.  This client is a read-only consumer.

The in-memory cache is intentionally short-lived (60s default) so that
permission/role changes propagate quickly without requiring explicit
invalidation in most cases.
"""

import time
from uuid import UUID

import httpx
from tr_shared.http.circuit_breaker import CircuitBreaker

from shared_auth_lib.config import get_settings
from shared_auth_lib.exceptions import AuthContextNotFoundError
from shared_auth_lib.logging import get_logger
from shared_auth_lib.models.auth_context import AuthContext

logger = get_logger(__name__)


class AuthContextClient:
    """Fetch AuthContext from CRM-backend's internal API.

    The CRM-backend endpoint handles caching internally:
    - Checks Redis cache first
    - Falls back to database on cache miss
    - Populates cache for subsequent requests

    This client reuses a single httpx.AsyncClient for connection
    pooling across requests. Call close() during application
    shutdown.
    """

    def __init__(
        self,
        crm_backend_url: str,
        service_token: str,
        timeout: float | None = None,
        circuit_failure_threshold: int = 10,
        circuit_recovery_timeout: int = 15,
        local_cache_ttl: int = 60,
        local_cache_max_size: int = 1000,
    ) -> None:
        self._crm_backend_url = crm_backend_url.rstrip("/")
        self._service_token = service_token
        self._timeout = (
            timeout
            if timeout is not None
            else get_settings().AUTH_CONTEXT_REQUEST_TIMEOUT
        )
        self._client = httpx.AsyncClient(
            base_url=self._crm_backend_url,
            timeout=httpx.Timeout(self._timeout),
        )
        self._circuit = CircuitBreaker(
            name="auth-context-client",
            failure_threshold=circuit_failure_threshold,
            recovery_timeout=circuit_recovery_timeout,
        )
        # In-memory cache: {external_auth_id_str: (expires_at_monotonic, AuthContext)}
        self._local_cache: dict[str, tuple[float, AuthContext]] = {}
        self._local_cache_ttl = local_cache_ttl
        self._local_cache_max_size = local_cache_max_size

    async def get_auth_context(
        self,
        external_auth_id: UUID,
        correlation_id: str | None = None,
    ) -> AuthContext:
        """Fetch AuthContext by external_auth_id (Supabase Auth UUID).

        Checks the in-memory cache first (sub-millisecond).  On a cache
        miss, falls through to the HTTP call to CRM-backend (which has
        its own Redis cache).  Successful responses are cached locally
        for ``local_cache_ttl`` seconds.

        Args:
            external_auth_id: The Supabase Auth UUID (JWT sub claim).
            correlation_id: Optional correlation ID for distributed
                tracing. Forwarded as X-Correlation-ID header.

        Returns:
            AuthContext instance with roles, permissions, tenant info.

        Raises:
            AuthContextNotFoundError: If user not found or service
                unreachable.
        """
        cache_key = str(external_auth_id)

        # 1. Check in-memory cache first (0.001ms)
        cached = self._get_from_local_cache(cache_key)
        if cached is not None:
            logger.debug(
                "auth_context_local_cache_hit",
                extra={"external_auth_id": cache_key},
            )
            return cached

        logger.debug(
            "auth_context_local_cache_miss",
            extra={"external_auth_id": cache_key},
        )

        # 2. Circuit breaker check
        if await self._circuit.is_open():
            logger.warning(
                "auth_context_circuit_open",
                extra={"external_auth_id": cache_key},
            )
            raise AuthContextNotFoundError(
                "Circuit open: CRM-backend unavailable"
            )

        # 3. HTTP call to CRM-backend
        url = (
            f"/api/v1/internal/auth-context/{external_auth_id}"
        )
        headers: dict[str, str] = {
            "X-Service-Token": self._service_token,
        }
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id

        try:
            response = await self._client.get(
                url, headers=headers
            )
            response.raise_for_status()
            data = response.json()
            # CRM-backend wraps responses in {"status": "...", "data": {...}}
            # Extract the inner "data" dict if present.
            if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
                data = data["data"]
            result = AuthContext(**data)
            await self._circuit.record_success()

            # 4. Store in local cache for subsequent requests
            self._put_in_local_cache(cache_key, result)

            return result
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                # 404 is a logical "not found" — not a service failure
                raise AuthContextNotFoundError(
                    f"AuthContext not found for "
                    f"{external_auth_id}"
                ) from exc
            logger.error(
                "auth_context_fetch_http_error",
                extra={
                    "status_code": exc.response.status_code,
                    "external_auth_id": cache_key,
                },
            )
            await self._circuit.record_failure()
            raise AuthContextNotFoundError(
                f"Failed to fetch AuthContext: "
                f"HTTP {exc.response.status_code}"
            ) from exc
        except httpx.TimeoutException as exc:
            logger.error(
                "auth_context_fetch_timeout",
                extra={"external_auth_id": cache_key},
            )
            await self._circuit.record_failure()
            raise AuthContextNotFoundError(
                f"Timeout fetching AuthContext for "
                f"{external_auth_id}"
            ) from exc
        except Exception as exc:
            logger.error(
                "auth_context_fetch_failed",
                extra={
                    "error": str(exc),
                    "external_auth_id": cache_key,
                },
                exc_info=True,
            )
            await self._circuit.record_failure()
            raise AuthContextNotFoundError(
                f"Failed to fetch AuthContext: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # In-memory cache helpers
    # ------------------------------------------------------------------

    def _get_from_local_cache(self, key: str) -> AuthContext | None:
        """Return cached AuthContext if present and not expired."""
        entry = self._local_cache.get(key)
        if entry is None:
            return None
        expires_at, auth_ctx = entry
        if time.monotonic() > expires_at:
            del self._local_cache[key]
            return None
        return auth_ctx

    def _put_in_local_cache(self, key: str, value: AuthContext) -> None:
        """Store AuthContext in local cache with TTL."""
        if len(self._local_cache) >= self._local_cache_max_size:
            # Evict the oldest entry (first inserted)
            oldest_key = next(iter(self._local_cache))
            del self._local_cache[oldest_key]
        self._local_cache[key] = (
            time.monotonic() + self._local_cache_ttl,
            value,
        )

    def invalidate_local_cache(
        self, external_auth_id: UUID | None = None
    ) -> None:
        """Invalidate local cache entries.

        Args:
            external_auth_id: If provided, invalidate only that user.
                If None, clear the entire local cache.
        """
        if external_auth_id is not None:
            self._local_cache.pop(str(external_auth_id), None)
        else:
            self._local_cache.clear()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client and clear local cache."""
        self._local_cache.clear()
        await self._client.aclose()

    async def __aenter__(self) -> "AuthContextClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
