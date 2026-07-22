"""Auth feature permission constants. Scheme: {feature}:{action}.

Canonical strings for the auth module's scopes (user / role / credential /
credential_type / email + system:admin + audit:read). crm-core's
`AuthPermission` enum references these so the string is defined once here.
`admin:read` is NOT here — it lives in `permissions.admin`.
"""

SYSTEM_ADMIN = "system:admin"
AUDIT_READ = "audit:read"

USER_CREATE = "user:create"
USER_MANAGE = "user:manage"
USER_SUSPEND = "user:suspend"

ROLE_CREATE = "role:create"
ROLE_ASSIGN = "role:assign"

CREDENTIAL_CREATE = "credential:create"
CREDENTIAL_READ = "credential:read"
CREDENTIAL_UPDATE = "credential:update"
CREDENTIAL_DELETE = "credential:delete"
CREDENTIAL_READ_SECRET = "credential:read_secret"

CREDENTIAL_TYPE_CREATE = "credential_type:create"
CREDENTIAL_TYPE_READ = "credential_type:read"
CREDENTIAL_TYPE_UPDATE = "credential_type:update"
CREDENTIAL_TYPE_DELETE = "credential_type:delete"

EMAIL_SEND = "email:send"
EMAIL_BULK_SEND = "email:bulk_send"
EMAIL_READ_TEMPLATES = "email:read_templates"
EMAIL_READ_STATS = "email:read_stats"
EMAIL_READ_PROVIDERS = "email:read_providers"
EMAIL_READ_HEALTH = "email:read_health"
EMAIL_READ_LOGS = "email:read_logs"

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
