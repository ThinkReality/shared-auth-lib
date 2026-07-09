"""HR feature permission constants. Scheme: {feature}:{action}.

The 9 live strings already DB-migrated to the hr:* feature scheme (crm-core
migration crm_061). Actions are compound (attendance_read, employees_sync, …);
they are kept verbatim because they are granted in the permission table.

The 5 recruitment strings below are an intentional exception: 3-part
({feature}:{resource}:{action}) granularity, registered under the
`recruitment` Feature-spine member (added alongside this change) rather than
`hr`, because recruitment is people-finance's HR module but is itself a
distinct bounded context (job postings/applications) — matching the
Feature-spine's own "frontend feature / domain / bounded context" criterion.
Values are frozen — already granted in tr-crm-core's auth catalog
(migration crm_070) and enforced as local constants in tr-people-finance.
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

HR_RECRUITMENT_APPLICATION_READ = "recruitment:application:read"
HR_RECRUITMENT_APPLICATION_UPDATE = "recruitment:application:update"
HR_RECRUITMENT_POSTING_CREATE = "recruitment:posting:create"
HR_RECRUITMENT_POSTING_PUBLISH = "recruitment:posting:publish"
HR_RECRUITMENT_POSTING_UPDATE = "recruitment:posting:update"

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
    "HR_RECRUITMENT_APPLICATION_READ",
    "HR_RECRUITMENT_APPLICATION_UPDATE",
    "HR_RECRUITMENT_POSTING_CREATE",
    "HR_RECRUITMENT_POSTING_PUBLISH",
    "HR_RECRUITMENT_POSTING_UPDATE",
]
