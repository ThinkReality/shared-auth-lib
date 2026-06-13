"""Shared permission constants (per-feature modules)."""

from shared_auth_lib.permissions.finance import (
    FINANCE_EXPORT,
    FINANCE_VIEW,
    FINANCE_WRITE,
)
from shared_auth_lib.permissions.hr import (
    HR_ATTENDANCE_APPROVE,
    HR_ATTENDANCE_EXCEPTIONS_MANAGE,
    HR_ATTENDANCE_EXPORT,
    HR_ATTENDANCE_MANUAL_CREATE,
    HR_ATTENDANCE_READ,
    HR_ATTENDANCE_SYNC,
    HR_EMPLOYEES_READ,
    HR_EMPLOYEES_SYNC,
    HR_HIKCENTRAL_READ,
)
from shared_auth_lib.permissions.lead import (
    LEAD_ASSIGN,
    LEAD_CLAIM,
    LEAD_CREATE,
    LEAD_DELETE,
    LEAD_UPDATE,
    LEAD_VIEW,
)
from shared_auth_lib.permissions.listing import (
    LISTING_CREATE,
    LISTING_DELETE,
    LISTING_UPDATE,
    LISTING_VIEW,
)
from shared_auth_lib.permissions.media import (
    MEDIA_DELETE,
    MEDIA_UPDATE,
    MEDIA_UPLOAD,
    MEDIA_VIEW,
)
from shared_auth_lib.permissions.task import (
    TASK_ASSIGN,
    TASK_CREATE,
    TASK_DELETE,
    TASK_EDIT,
    TASK_VIEW,
)

__all__ = [
    # finance
    "FINANCE_EXPORT",
    "FINANCE_VIEW",
    "FINANCE_WRITE",
    # hr
    "HR_ATTENDANCE_APPROVE",
    "HR_ATTENDANCE_EXCEPTIONS_MANAGE",
    "HR_ATTENDANCE_EXPORT",
    "HR_ATTENDANCE_MANUAL_CREATE",
    "HR_ATTENDANCE_READ",
    "HR_ATTENDANCE_SYNC",
    "HR_EMPLOYEES_READ",
    "HR_EMPLOYEES_SYNC",
    "HR_HIKCENTRAL_READ",
    # lead
    "LEAD_ASSIGN",
    "LEAD_CLAIM",
    "LEAD_CREATE",
    "LEAD_DELETE",
    "LEAD_UPDATE",
    "LEAD_VIEW",
    # listing
    "LISTING_CREATE",
    "LISTING_DELETE",
    "LISTING_UPDATE",
    "LISTING_VIEW",
    # media
    "MEDIA_DELETE",
    "MEDIA_UPDATE",
    "MEDIA_UPLOAD",
    "MEDIA_VIEW",
    # task
    "TASK_ASSIGN",
    "TASK_CREATE",
    "TASK_DELETE",
    "TASK_EDIT",
    "TASK_VIEW",
]
