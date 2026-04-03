"""Library-specific exceptions for shared-auth-lib."""


class SharedAuthError(Exception):
    """Base exception for shared-auth-lib."""


class InvalidIdentityHeaderError(SharedAuthError):
    """Raised when identity headers contain invalid data."""


class AuthContextNotFoundError(SharedAuthError):
    """Raised when AuthContext cannot be fetched from CRM-backend."""
