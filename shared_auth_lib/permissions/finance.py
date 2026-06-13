"""Finance feature permission constants. Scheme: {feature}:{action}.

Ports the live strings from tr-people-finance. ``write`` deviates from the
preferred verbs (no view/edit split today); kept verbatim — a verb migration is
a separate, DB-backed change.
"""

FINANCE_VIEW = "finance:read"
FINANCE_WRITE = "finance:write"
FINANCE_EXPORT = "finance:export"

__all__ = [
    "FINANCE_EXPORT",
    "FINANCE_VIEW",
    "FINANCE_WRITE",
]
