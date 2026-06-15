"""Admin feature permission constants. Scheme: {feature}:{action}.

Ports the live require_permission string from tr-crm-core. (admin:write /
admin:operations are gateway S2S service-token scopes — a different taxonomy,
not user RBAC feature permissions — so they are intentionally not here.)
"""

ADMIN_READ = "admin:read"

__all__ = [
    "ADMIN_READ",
]
