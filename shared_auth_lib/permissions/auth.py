"""Auth feature permission constants. Scheme: auth:{resource}:{action}.

Domain-prefixed (`AUTH_*`) + flat-exported from the package root, matching every
other domain module. Values are feature-prefixed `auth:` so the prefix is a
`Feature`-spine member (D-PERMSCHEME). `admin:read` is NOT here — it lives in
`permissions.admin` (`admin` is its own Feature).
"""

AUTH_SYSTEM_ADMIN = "auth:system:admin"
AUTH_AUDIT_READ = "auth:audit:read"

AUTH_USER_CREATE = "auth:user:create"
AUTH_USER_MANAGE = "auth:user:manage"
AUTH_USER_SUSPEND = "auth:user:suspend"

# Merging two directory identities is not "managing a user": it is hard to undo and
# no existing string honestly covers it. The directory list reuses AUTH_USER_MANAGE and
# invite reuses AUTH_USER_CREATE, so this is the only new string the directory needs.
AUTH_DIRECTORY_MERGE = "auth:directory:merge"

AUTH_ROLE_CREATE = "auth:role:create"
AUTH_ROLE_ASSIGN = "auth:role:assign"

AUTH_CREDENTIAL_CREATE = "auth:credential:create"
AUTH_CREDENTIAL_READ = "auth:credential:read"
AUTH_CREDENTIAL_UPDATE = "auth:credential:update"
AUTH_CREDENTIAL_DELETE = "auth:credential:delete"
AUTH_CREDENTIAL_READ_SECRET = "auth:credential:read_secret"

AUTH_CREDENTIAL_TYPE_CREATE = "auth:credential_type:create"
AUTH_CREDENTIAL_TYPE_READ = "auth:credential_type:read"
AUTH_CREDENTIAL_TYPE_UPDATE = "auth:credential_type:update"
AUTH_CREDENTIAL_TYPE_DELETE = "auth:credential_type:delete"

__all__ = [
    "AUTH_SYSTEM_ADMIN",
    "AUTH_AUDIT_READ",
    "AUTH_USER_CREATE",
    "AUTH_USER_MANAGE",
    "AUTH_USER_SUSPEND",
    "AUTH_DIRECTORY_MERGE",
    "AUTH_ROLE_CREATE",
    "AUTH_ROLE_ASSIGN",
    "AUTH_CREDENTIAL_CREATE",
    "AUTH_CREDENTIAL_READ",
    "AUTH_CREDENTIAL_UPDATE",
    "AUTH_CREDENTIAL_DELETE",
    "AUTH_CREDENTIAL_READ_SECRET",
    "AUTH_CREDENTIAL_TYPE_CREATE",
    "AUTH_CREDENTIAL_TYPE_READ",
    "AUTH_CREDENTIAL_TYPE_UPDATE",
    "AUTH_CREDENTIAL_TYPE_DELETE",
]
