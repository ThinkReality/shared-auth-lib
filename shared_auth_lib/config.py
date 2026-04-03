"""Configuration for shared-auth-lib."""

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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


@lru_cache()
def get_settings() -> AuthLibSettings:
    """Return the global AuthLibSettings instance."""
    return AuthLibSettings()
