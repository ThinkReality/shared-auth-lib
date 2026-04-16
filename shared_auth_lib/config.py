"""Configuration for shared-auth-lib."""

from functools import lru_cache
from uuid import UUID

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_ENVIRONMENTS = {"dev", "development", "local"}
_DEV_UUID = UUID("00000000-0000-0000-0000-000000000001")


class AuthLibSettings(BaseSettings):
    """Configuration for shared-auth-lib.

    Downstream services set these via environment variables.
    The AUTH_LIB_ prefix is stripped automatically by pydantic-settings.

    Secret generation::

        # Generate GATEWAY_SIGNING_SECRET (32-byte hex, must match API gateway):
        openssl rand -hex 32

        # Generate SERVICE_TOKEN (for S2S calls to CRM-backend):
        openssl rand -base64 32
    """

    GATEWAY_SIGNING_SECRET: str
    ENVIRONMENT: str = "development"
    CRM_BACKEND_URL: str = "http://crm-backend:8000"
    SERVICE_TOKEN: str = ""
    GATEWAY_TIMESTAMP_TOLERANCE: int = 30
    AUTH_CONTEXT_REQUEST_TIMEOUT: float = 5.0

    # ── Dev mode bypass ──
    # When True, skips HMAC verification and injects a fake AuthContext
    # so you can curl any service directly without the API gateway.
    # Guarded: refuses to activate outside dev environments.
    DEV_MODE_BYPASS: bool = False
    DEV_USER_ID: UUID = Field(default=_DEV_UUID)
    DEV_TENANT_ID: UUID = Field(default=_DEV_UUID)
    DEV_ROLES: list[str] = Field(default=["ADMIN"])
    DEV_PERMISSIONS: list[str] = Field(default=["*"])
    DEV_EMAIL: str = "dev@thinkrealty.local"

    model_config = SettingsConfigDict(
        env_prefix="AUTH_LIB_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_production_config(self) -> "AuthLibSettings":
        if self.ENVIRONMENT in ("production", "staging"):
            if not self.SERVICE_TOKEN or not self.SERVICE_TOKEN.strip():
                raise ValueError(
                    "AUTH_LIB_SERVICE_TOKEN must not be empty in "
                    f"{self.ENVIRONMENT}"
                )
            if not self.GATEWAY_SIGNING_SECRET.strip():
                raise ValueError(
                    "AUTH_LIB_GATEWAY_SIGNING_SECRET must not be "
                    f"blank in {self.ENVIRONMENT}"
                )
            if "localhost" in self.CRM_BACKEND_URL:
                raise ValueError(
                    "AUTH_LIB_CRM_BACKEND_URL must not point to "
                    f"localhost in {self.ENVIRONMENT}"
                )
        return self

    @model_validator(mode="after")
    def validate_dev_bypass(self) -> "AuthLibSettings":
        if not self.DEV_MODE_BYPASS:
            return self
        if self.ENVIRONMENT not in _DEV_ENVIRONMENTS:
            raise ValueError(
                f"AUTH_LIB_DEV_MODE_BYPASS=true is only allowed when "
                f"AUTH_LIB_ENVIRONMENT is one of {_DEV_ENVIRONMENTS}, "
                f"but got '{self.ENVIRONMENT}'. This is a safety guard "
                f"to prevent dev mode from running in production."
            )
        return self


@lru_cache()
def get_settings() -> AuthLibSettings:
    """Return the global AuthLibSettings instance."""
    return AuthLibSettings()
