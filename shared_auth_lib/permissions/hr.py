"""HR feature permission constants. Scheme: {feature}:{action}.

The 9 live strings already DB-migrated to the hr:* feature scheme (crm-core
migration crm_061). Actions are compound (attendance_read, employees_sync, …);
they are kept verbatim because they are granted in the permission table.
"""

HR_ATTENDANCE_READ = "hr:attendance_read"
HR_ATTENDANCE_EXPORT = "hr:attendance_export"
HR_ATTENDANCE_SYNC = "hr:attendance_sync"
HR_ATTENDANCE_MANUAL_CREATE = "hr:attendance_manual_create"
HR_ATTENDANCE_APPROVE = "hr:attendance_approve"
HR_ATTENDANCE_EXCEPTIONS_MANAGE = "hr:attendance_exceptions_manage"
HR_EMPLOYEES_READ = "hr:employees_read"
HR_EMPLOYEES_SYNC = "hr:employees_sync"
HR_HIKCENTRAL_READ = "hr:hikcentral_read"

__all__ = [
    "HR_ATTENDANCE_APPROVE",
    "HR_ATTENDANCE_EXCEPTIONS_MANAGE",
    "HR_ATTENDANCE_EXPORT",
    "HR_ATTENDANCE_MANUAL_CREATE",
    "HR_ATTENDANCE_READ",
    "HR_ATTENDANCE_SYNC",
    "HR_EMPLOYEES_READ",
    "HR_EMPLOYEES_SYNC",
    "HR_HIKCENTRAL_READ",
]
