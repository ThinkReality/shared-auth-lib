"""Admin feature permission constants. Scheme: {feature}:{action}.

Ports the live require_permission strings from tr-crm-core.

``admin:read`` / ``admin:write`` gate the admin control plane as a whole — every
business route in crm-core's admin module (modules, dashboard, lead scoring,
nurture, followup, assignment, integrations, monitoring, agents, agent groups,
WhatsApp config). Coarse on purpose: the admin panel is one capability with one
audience, and no consumer asks to grant a subset of it. Split a feature out into
its own ``admin:<feature>:<action>`` set only when something actually needs to
be delegated separately — which is exactly why the site registry below is
already split out: a site key is a bearer credential, so issuing and rotating
one carries a blast radius the rest of the admin panel does not.

``admin:operations`` is NOT here: it is a gateway S2S service-token scope
(``ServicePermission``), a separate taxonomy from user RBAC.
"""

ADMIN_READ = "admin:read"
ADMIN_WRITE = "admin:write"
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
    "ADMIN_WRITE",
]
