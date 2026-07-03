"""Finance feature permission constants.

Two coexisting schemes:
- coarse ``{feature}:{action}`` — the original broad grants (read/write/export).
- granular ``{feature}:{resource}:{action}`` — Plan 09 split, so an expense
  approver cannot also create GL accounts. The 3-part colon form is what the
  gateway ``finance:<resource>:*`` wildcard matches against.

``write`` deviates from the preferred verbs (no view/edit split today); kept
verbatim — a verb migration is a separate, DB-backed change.
"""

FINANCE_VIEW = "finance:read"
FINANCE_WRITE = "finance:write"
FINANCE_EXPORT = "finance:export"

# ── granular (Plan 09) — 3-part colon scheme ─────────────────────────────────
FINANCE_EXPENSES_READ = "finance:expenses:read"
FINANCE_EXPENSES_WRITE = "finance:expenses:write"
FINANCE_EXPENSES_APPROVE = "finance:expenses:approve"
FINANCE_INVOICES_READ = "finance:invoices:read"
FINANCE_INVOICES_WRITE = "finance:invoices:write"
FINANCE_INVOICES_SEND = "finance:invoices:send"
FINANCE_ADMIN = "finance:admin"

__all__ = [
    "FINANCE_ADMIN",
    "FINANCE_EXPENSES_APPROVE",
    "FINANCE_EXPENSES_READ",
    "FINANCE_EXPENSES_WRITE",
    "FINANCE_EXPORT",
    "FINANCE_INVOICES_READ",
    "FINANCE_INVOICES_SEND",
    "FINANCE_INVOICES_WRITE",
    "FINANCE_VIEW",
    "FINANCE_WRITE",
]
