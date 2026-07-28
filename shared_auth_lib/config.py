"""Configuration for shared-auth-lib."""

from functools import lru_cache
from uuid import UUID

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from tr_shared.contracts import Environment

_DEV_UUID = UUID("00000000-0000-0000-0000-000000000001")


class AuthLibSettings(BaseSettings):
    """Configuration for shared-auth-lib.

    Downstream services set these via environment variables.
    The AUTH_LIB_ prefix is stripped automatically by pydantic-settings.
    """

    GATEWAY_SIGNING_SECRET: str
    # Reads the PLATFORM variable, not AUTH_LIB_ENVIRONMENT. One concept, one
    # variable: the prefixed form used to shadow this, so a service's own bypass
    # validator could pass while this guard saw a different value.
    ENVIRONMENT: Environment = Field(
        default=Environment.DEVELOPMENT,
        validation_alias="ENVIRONMENT",
    )
    CRM_CORE_URL: str = "http://tr-crm-core:8000"
    SERVICE_TOKEN: str = ""
    GATEWAY_TIMESTAMP_TOLERANCE: int = 30
    AUTH_CONTEXT_REQUEST_TIMEOUT: float = 5.0

    # Skips HMAC verification and injects a fake AuthContext; guarded to dev environments only.
    DEV_MODE_BYPASS: bool = False
    DEV_USER_ID: UUID = Field(default=_DEV_UUID)
    DEV_TENANT_ID: UUID = Field(default=_DEV_UUID)
    DEV_ROLES: list[str] = Field(default=["admin"])
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
        if self.ENVIRONMENT in (Environment.PRODUCTION, Environment.STAGING):
            if not self.SERVICE_TOKEN or not self.SERVICE_TOKEN.strip():
                raise ValueError(
                    f"AUTH_LIB_SERVICE_TOKEN must not be empty in {self.ENVIRONMENT}"
                )
            if not self.GATEWAY_SIGNING_SECRET.strip():
                raise ValueError(
                    "AUTH_LIB_GATEWAY_SIGNING_SECRET must not be "
                    f"blank in {self.ENVIRONMENT}"
                )
            if "localhost" in self.CRM_CORE_URL:
                raise ValueError(
                    "AUTH_LIB_CRM_CORE_URL must not point to "
                    f"localhost in {self.ENVIRONMENT}"
                )
        return self

    @model_validator(mode="after")
    def validate_dev_bypass(self) -> "AuthLibSettings":
        if not self.DEV_MODE_BYPASS:
            return self
        if not self.ENVIRONMENT.is_local:
            raise ValueError(
                f"AUTH_LIB_DEV_MODE_BYPASS=true is only allowed when ENVIRONMENT "
                f"is 'development' or 'test', but got '{self.ENVIRONMENT}'. This "
                f"is a safety guard to prevent dev mode from running in production."
            )
        return self


@lru_cache()
def get_settings() -> AuthLibSettings:
    """Return the global AuthLibSettings instance."""
    return AuthLibSettings()
