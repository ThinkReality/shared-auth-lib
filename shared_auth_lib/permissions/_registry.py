"""Seedable registry of every platform permission.

`ALL_PERMISSIONS` is the single source crm-core seeds `auth_permissions` from.
Each entry is derived from the per-domain constant modules — add a new
permission by adding its constant to the domain module AND an entry here.

resource = first colon segment; action = remaining segments joined with "_".
"""

from dataclasses import dataclass

from shared_auth_lib.permissions import (
    admin,
    auth,
    dld,
    finance,
    hr,
    lead,
    listing,
    lms,
    media,
    scraping,
    task,
)


@dataclass(frozen=True, slots=True)
class PermissionDef:
    name: str
    resource: str
    action: str
    description: str


def _d(name: str, description: str) -> PermissionDef:
    resource, _, rest = name.partition(":")
    return PermissionDef(
        name=name,
        resource=resource,
        action=rest.replace(":", "_"),
        description=description,
    )


ALL_PERMISSIONS: tuple[PermissionDef, ...] = (
    # auth
    _d(auth.SYSTEM_ADMIN, "Full system administration"),
    _d(auth.AUDIT_READ, "Read audit logs"),
    _d(auth.USER_CREATE, "Create users"),
    _d(auth.USER_MANAGE, "Manage users"),
    _d(auth.USER_SUSPEND, "Suspend users"),
    _d(auth.ROLE_CREATE, "Create roles"),
    _d(auth.ROLE_ASSIGN, "Assign roles to users"),
    _d(auth.CREDENTIAL_CREATE, "Create credentials"),
    _d(auth.CREDENTIAL_READ, "Read credentials"),
    _d(auth.CREDENTIAL_UPDATE, "Update credentials"),
    _d(auth.CREDENTIAL_DELETE, "Delete credentials"),
    _d(auth.CREDENTIAL_READ_SECRET, "Read credential secret values"),
    _d(auth.CREDENTIAL_TYPE_CREATE, "Create credential types"),
    _d(auth.CREDENTIAL_TYPE_READ, "Read credential types"),
    _d(auth.CREDENTIAL_TYPE_UPDATE, "Update credential types"),
    _d(auth.CREDENTIAL_TYPE_DELETE, "Delete credential types"),
    _d(auth.EMAIL_SEND, "Send email"),
    _d(auth.EMAIL_BULK_SEND, "Send bulk email"),
    _d(auth.EMAIL_READ_TEMPLATES, "Read email templates"),
    _d(auth.EMAIL_READ_STATS, "Read email stats"),
    _d(auth.EMAIL_READ_PROVIDERS, "Read email providers"),
    _d(auth.EMAIL_READ_HEALTH, "Read email health"),
    _d(auth.EMAIL_READ_LOGS, "Read email logs"),
    # admin
    _d(admin.ADMIN_READ, "Read admin resources"),
    _d(admin.ADMIN_WEBHOOK_REPLAY, "Replay admin webhooks"),
    # media
    _d(media.MEDIA_VIEW, "Read media"),
    _d(media.MEDIA_UPLOAD, "Upload media"),
    _d(media.MEDIA_UPDATE, "Update media"),
    _d(media.MEDIA_DELETE, "Delete media"),
    _d(media.MEDIA_BILLING_READ, "Read media billing"),
    _d(media.MEDIA_USAGE_READ, "Read media usage"),
    _d(media.MEDIA_QUOTA_READ, "Read media quotas"),
    _d(media.MEDIA_QUOTA_MANAGE, "Manage media quotas"),
    # lead
    _d(lead.LEAD_VIEW, "Read leads"),
    _d(lead.LEAD_CREATE, "Create leads"),
    _d(lead.LEAD_UPDATE, "Update leads"),
    _d(lead.LEAD_DELETE, "Delete leads"),
    _d(lead.LEAD_ASSIGN, "Assign leads"),
    _d(lead.LEAD_CLAIM, "Claim leads"),
    # listing
    _d(listing.LISTING_VIEW, "Read listings"),
    _d(listing.LISTING_CREATE, "Create listings"),
    _d(listing.LISTING_UPDATE, "Update listings"),
    _d(listing.LISTING_DELETE, "Delete listings"),
    # hr
    _d(hr.HR_ATTENDANCE_READ, "Read attendance"),
    _d(hr.HR_ATTENDANCE_EXPORT, "Export attendance"),
    _d(hr.HR_ATTENDANCE_SYNC, "Sync attendance"),
    _d(hr.HR_ATTENDANCE_MANUAL_CREATE, "Manually create attendance"),
    _d(hr.HR_ATTENDANCE_APPROVE, "Approve attendance"),
    _d(hr.HR_ATTENDANCE_EXCEPTIONS_MANAGE, "Manage attendance exceptions"),
    _d(hr.HR_EMPLOYEES_READ, "Read employees"),
    _d(hr.HR_EMPLOYEES_SYNC, "Sync employees"),
    _d(hr.HR_HIKCENTRAL_READ, "Read HikCentral data"),
    _d(hr.HR_RECRUITMENT_APPLICATION_READ, "Read job applications"),
    _d(hr.HR_RECRUITMENT_APPLICATION_UPDATE, "Update job applications"),
    _d(hr.HR_RECRUITMENT_POSTING_CREATE, "Create job postings"),
    _d(hr.HR_RECRUITMENT_POSTING_PUBLISH, "Publish job postings"),
    _d(hr.HR_RECRUITMENT_POSTING_UPDATE, "Update job postings"),
    # finance
    _d(finance.FINANCE_VIEW, "Read finance"),
    _d(finance.FINANCE_WRITE, "Write finance"),
    _d(finance.FINANCE_EXPORT, "Export finance data"),
    _d(finance.FINANCE_EXPENSES_READ, "Read expenses"),
    _d(finance.FINANCE_EXPENSES_WRITE, "Write expenses"),
    _d(finance.FINANCE_EXPENSES_APPROVE, "Approve expenses"),
    _d(finance.FINANCE_INVOICES_READ, "Read invoices"),
    _d(finance.FINANCE_INVOICES_WRITE, "Write invoices"),
    _d(finance.FINANCE_INVOICES_SEND, "Send invoices"),
    _d(finance.FINANCE_ADMIN, "Finance administration"),
    # lms
    _d(lms.LMS_AGENT_VIEW_STATS, "View LMS agent stats"),
    _d(lms.LMS_ASSIGNMENT_CREATE, "Create LMS assignments"),
    _d(lms.LMS_QUIZ_PUBLISH, "Publish LMS quizzes"),
    _d(lms.LMS_QUIZ_VIEW_PROGRESS, "View LMS quiz progress"),
    # task
    _d(task.TASK_VIEW, "View tasks"),
    _d(task.TASK_CREATE, "Create tasks"),
    _d(task.TASK_EDIT, "Edit tasks"),
    _d(task.TASK_DELETE, "Delete tasks"),
    _d(task.TASK_ASSIGN, "Assign tasks"),
    # dld
    _d(dld.DLD_SYNC_MANAGE, "Manage DLD sync"),
    _d(dld.DLD_DATASETS_UPLOAD, "Upload DLD datasets"),
    _d(dld.DLD_OWNERS_READ, "Read DLD owner records"),
    _d(dld.DLD_OWNERS_CONTACT, "Read DLD owner contact details"),
    _d(dld.DLD_OWNERS_IDENTITY, "Read DLD owner identity details"),
    # property (realty scraping area)
    _d(scraping.PROPERTY_SCRAPING_CACHE_FLUSH, "Flush the property scraper cache"),
)


def permission_names() -> frozenset[str]:
    return frozenset(p.name for p in ALL_PERMISSIONS)
