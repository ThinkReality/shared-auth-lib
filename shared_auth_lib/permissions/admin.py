"""Admin feature permission constants. Scheme: {feature}:{action}.

Ports the live require_permission strings from tr-crm-core. (admin:write /
admin:operations are gateway S2S service-token scopes — a different taxonomy,
not user RBAC feature permissions — so they are intentionally not here.)
"""

ADMIN_READ = "admin:read"
ADMIN_WEBHOOK_REPLAY = "admin:webhook:replay"

__all__ = [
    "ADMIN_READ",
    "ADMIN_WEBHOOK_REPLAY",
]
