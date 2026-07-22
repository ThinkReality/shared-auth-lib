"""Media feature permission constants. Scheme: {feature}:{action}.

Ports the live require_permission strings from tr-media-service (CRUD +
billing/usage/quota domains).
"""

MEDIA_VIEW = "media:read"
MEDIA_UPLOAD = "media:upload"
MEDIA_UPDATE = "media:update"
MEDIA_DELETE = "media:delete"

MEDIA_BILLING_READ = "media:billing:read"
MEDIA_USAGE_READ = "media:usage:read"
MEDIA_QUOTA_READ = "media:quota:read"
MEDIA_QUOTA_MANAGE = "media:quota:manage"

__all__ = [
    "MEDIA_VIEW",
    "MEDIA_UPLOAD",
    "MEDIA_UPDATE",
    "MEDIA_DELETE",
    "MEDIA_BILLING_READ",
    "MEDIA_USAGE_READ",
    "MEDIA_QUOTA_READ",
    "MEDIA_QUOTA_MANAGE",
]
