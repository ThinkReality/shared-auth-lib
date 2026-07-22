"""Auth feature permission constants. Scheme: auth:{resource}:{action}.

Canonical strings for the auth module's scopes (user / role / credential /
credential_type / email + system admin + audit). Every string is
feature-prefixed ``auth:`` so its prefix is a member of the platform
``Feature`` spine (D-PERMSCHEME). crm-core's `AuthPermission` enum references
these so the string is defined once here. `admin:read` is NOT here — it lives
in `permissions.admin` (`admin` is its own Feature).
"""

SYSTEM_ADMIN = "auth:system:admin"
AUDIT_READ = "auth:audit:read"

USER_CREATE = "auth:user:create"
USER_MANAGE = "auth:user:manage"
USER_SUSPEND = "auth:user:suspend"

ROLE_CREATE = "auth:role:create"
ROLE_ASSIGN = "auth:role:assign"

CREDENTIAL_CREATE = "auth:credential:create"
CREDENTIAL_READ = "auth:credential:read"
CREDENTIAL_UPDATE = "auth:credential:update"
CREDENTIAL_DELETE = "auth:credential:delete"
CREDENTIAL_READ_SECRET = "auth:credential:read_secret"

CREDENTIAL_TYPE_CREATE = "auth:credential_type:create"
CREDENTIAL_TYPE_READ = "auth:credential_type:read"
CREDENTIAL_TYPE_UPDATE = "auth:credential_type:update"
CREDENTIAL_TYPE_DELETE = "auth:credential_type:delete"

EMAIL_SEND = "auth:email:send"
EMAIL_BULK_SEND = "auth:email:bulk_send"
EMAIL_READ_TEMPLATES = "auth:email:read_templates"
EMAIL_READ_STATS = "auth:email:read_stats"
EMAIL_READ_PROVIDERS = "auth:email:read_providers"
EMAIL_READ_HEALTH = "auth:email:read_health"
EMAIL_READ_LOGS = "auth:email:read_logs"

__all__ = [
    "SYSTEM_ADMIN",
    "AUDIT_READ",
    "USER_CREATE",
    "USER_MANAGE",
    "USER_SUSPEND",
    "ROLE_CREATE",
    "ROLE_ASSIGN",
    "CREDENTIAL_CREATE",
    "CREDENTIAL_READ",
    "CREDENTIAL_UPDATE",
    "CREDENTIAL_DELETE",
    "CREDENTIAL_READ_SECRET",
    "CREDENTIAL_TYPE_CREATE",
    "CREDENTIAL_TYPE_READ",
    "CREDENTIAL_TYPE_UPDATE",
    "CREDENTIAL_TYPE_DELETE",
    "EMAIL_SEND",
    "EMAIL_BULK_SEND",
    "EMAIL_READ_TEMPLATES",
    "EMAIL_READ_STATS",
    "EMAIL_READ_PROVIDERS",
    "EMAIL_READ_HEALTH",
    "EMAIL_READ_LOGS",
]
