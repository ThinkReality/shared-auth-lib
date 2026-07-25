"""Admin feature permission constants. Scheme: {feature}:{action}.

Ports the live require_permission strings from tr-crm-core. (admin:write /
admin:operations are gateway S2S service-token scopes — a different taxonomy,
not user RBAC feature permissions — so they are intentionally not here.)
"""

ADMIN_READ = "admin:read"
ADMIN_WEBHOOK_REPLAY = "admin:webhook:replay"

# Tenant site registry. Note `key_rotate`, not `key:rotate` — the conformance
# regex in tests/test_permissions.py allows at most 3 colon-separated segments.
ADMIN_SITE_READ = "admin:site:read"
ADMIN_SITE_CREATE = "admin:site:create"
ADMIN_SITE_UPDATE = "admin:site:update"
ADMIN_SITE_DELETE = "admin:site:delete"
ADMIN_SITE_KEY_ROTATE = "admin:site:key_rotate"

__all__ = [
    "ADMIN_READ",
    "ADMIN_SITE_CREATE",
    "ADMIN_SITE_DELETE",
    "ADMIN_SITE_KEY_ROTATE",
    "ADMIN_SITE_READ",
    "ADMIN_SITE_UPDATE",
    "ADMIN_WEBHOOK_REPLAY",
]
