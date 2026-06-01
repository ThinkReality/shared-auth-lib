"""HR permission constants shared by gateway-facing services."""

ATTENDANCE_READ = "attendance:read"
ATTENDANCE_EXPORT = "attendance:export"
ATTENDANCE_SYNC = "attendance:sync"
ATTENDANCE_MANUAL_CREATE = "attendance:manual_create"
ATTENDANCE_APPROVE = "attendance:approve"
ATTENDANCE_EXCEPTIONS_MANAGE = "attendance:exceptions_manage"
EMPLOYEES_READ = "employees:read"
EMPLOYEES_SYNC = "employees:sync"
HIKCENTRAL_READ = "hikcentral:read"

__all__ = [
    "ATTENDANCE_APPROVE",
    "ATTENDANCE_EXCEPTIONS_MANAGE",
    "ATTENDANCE_EXPORT",
    "ATTENDANCE_MANUAL_CREATE",
    "ATTENDANCE_READ",
    "ATTENDANCE_SYNC",
    "EMPLOYEES_READ",
    "EMPLOYEES_SYNC",
    "HIKCENTRAL_READ",
]
