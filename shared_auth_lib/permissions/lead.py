"""Lead feature permission constants. Scheme: {feature}:{action} (D-PERMSCHEME).

Ports the live strings used by tr-lead-management. ``read``/``update`` deviate
from the preferred ``view``/``edit`` verbs; they are kept verbatim because the
strings are already granted in the permission table (renaming needs a row
migration). ``claim`` is a lead-specific action.
"""

LEAD_VIEW = "lead:read"
LEAD_CREATE = "lead:create"
LEAD_UPDATE = "lead:update"
LEAD_DELETE = "lead:delete"
LEAD_ASSIGN = "lead:assign"
LEAD_CLAIM = "lead:claim"
LEAD_NOTE_DELETE = "lead:note_delete"
LEAD_DOCUMENT_DELETE = "lead:document_delete"
LEAD_MINE_POOL_ADMIN_VIEW = "lead:mine_pool_admin_read"

__all__ = [
    "LEAD_ASSIGN",
    "LEAD_CLAIM",
    "LEAD_CREATE",
    "LEAD_DELETE",
    "LEAD_DOCUMENT_DELETE",
    "LEAD_MINE_POOL_ADMIN_VIEW",
    "LEAD_NOTE_DELETE",
    "LEAD_UPDATE",
    "LEAD_VIEW",
]
