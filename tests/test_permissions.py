# tests/test_permissions.py
import importlib
import pkgutil
import re

import shared_auth_lib.permissions as permissions_pkg
from tr_shared.contracts.taxonomy import Feature

# D-PERMSCHEME (relaxed 2026-06-13; 3-part added 2026-07-03): every permission is
# {feature}:{action} (coarse) or {feature}:{resource}:{action} (granular, Plan 09,
# e.g. finance:expenses:read) where feature is a Feature-spine member and each
# remaining segment is a lowercase token. The eight PREFERRED verbs below stay the
# convention for NEW permissions, but compound actions (e.g. hr:attendance_read,
# media:upload) are permitted — they reflect live, DB-granted strings that cannot
# be renamed without a permission-row migration. Wildcards ("*") are grant-side
# data, never declared as constants.
PREFERRED_ACTIONS = {
    "view",
    "create",
    "edit",
    "delete",
    "export",
    "sync",
    "approve",
    "assign",
}
_FEATURES = {f.value for f in Feature}
_SCHEME = re.compile(r"^[a-z]+(:[a-z_]+){1,2}$")


def _iter_permission_modules():
    for info in pkgutil.iter_modules(permissions_pkg.__path__):
        if info.name.startswith("_"):
            continue
        yield importlib.import_module(f"shared_auth_lib.permissions.{info.name}")


def _constants(module) -> list[str]:
    return [getattr(module, name) for name in module.__all__]


def test_every_permission_module_follows_feature_action_scheme():
    """Sweep EVERY module in the permissions package — no per-module hard-coding.
    A non-Feature prefix or an off-vocabulary action anywhere fails here, so a new
    drifting module (e.g. `attendance:read`) cannot land silently."""
    modules = list(_iter_permission_modules())
    assert modules, "no permission modules discovered"
    seen = 0
    for module in modules:
        for perm in _constants(module):
            seen += 1
            assert "*" not in perm, (
                f"{perm!r}: wildcards are grant-side data, not lib constants"
            )
            assert _SCHEME.match(perm), (
                f"{perm!r} is not '{{feature}}:{{action}}' "
                f"or '{{feature}}:{{resource}}:{{action}}'"
            )
            feature = perm.split(":")[0]
            assert feature in _FEATURES, (
                f"{perm!r} prefix {feature!r} is not a Feature-spine member "
                f"({sorted(_FEATURES)})"
            )
    assert seen, "permission modules declared no constants"


def test_task_constants_importable_from_permissions_package():
    from shared_auth_lib.permissions import TASK_ASSIGN, TASK_VIEW

    assert TASK_VIEW == "task:view"
    assert TASK_ASSIGN == "task:assign"


def test_finance_granular_constants_importable_from_permissions_package():
    from shared_auth_lib.permissions import (
        FINANCE_ADMIN,
        FINANCE_EXPENSES_APPROVE,
        FINANCE_EXPENSES_READ,
        FINANCE_EXPENSES_WRITE,
        FINANCE_INVOICES_READ,
        FINANCE_INVOICES_SEND,
        FINANCE_INVOICES_WRITE,
    )

    assert FINANCE_EXPENSES_READ == "finance:expenses:read"
    assert FINANCE_EXPENSES_WRITE == "finance:expenses:write"
    assert FINANCE_EXPENSES_APPROVE == "finance:expenses:approve"
    assert FINANCE_INVOICES_READ == "finance:invoices:read"
    assert FINANCE_INVOICES_WRITE == "finance:invoices:write"
    assert FINANCE_INVOICES_SEND == "finance:invoices:send"
    assert FINANCE_ADMIN == "finance:admin"


def test_recruitment_granular_constants_importable_from_permissions_package():
    from shared_auth_lib.permissions import (
        HR_RECRUITMENT_APPLICATION_READ,
        HR_RECRUITMENT_APPLICATION_UPDATE,
        HR_RECRUITMENT_POSTING_CREATE,
        HR_RECRUITMENT_POSTING_PUBLISH,
        HR_RECRUITMENT_POSTING_UPDATE,
    )

    assert HR_RECRUITMENT_APPLICATION_READ == "recruitment:application:read"
    assert HR_RECRUITMENT_APPLICATION_UPDATE == "recruitment:application:update"
    assert HR_RECRUITMENT_POSTING_CREATE == "recruitment:posting:create"
    assert HR_RECRUITMENT_POSTING_PUBLISH == "recruitment:posting:publish"
    assert HR_RECRUITMENT_POSTING_UPDATE == "recruitment:posting:update"


def test_media_billing_usage_quota_constants_present():
    from shared_auth_lib.permissions import media

    assert media.MEDIA_BILLING_READ == "media:billing:read"
    assert media.MEDIA_USAGE_READ == "media:usage:read"
    assert media.MEDIA_QUOTA_READ == "media:quota:read"
    assert media.MEDIA_QUOTA_MANAGE == "media:quota:manage"


def test_admin_webhook_replay_constant_present():
    from shared_auth_lib.permissions import admin

    assert admin.ADMIN_WEBHOOK_REPLAY == "admin:webhook:replay"


def test_auth_module_constants_match_values():
    from shared_auth_lib.permissions import auth

    expected = {
        "AUTH_SYSTEM_ADMIN": "auth:system:admin",
        "AUTH_AUDIT_READ": "auth:audit:read",
        "AUTH_USER_CREATE": "auth:user:create",
        "AUTH_USER_MANAGE": "auth:user:manage",
        "AUTH_USER_SUSPEND": "auth:user:suspend",
        "AUTH_ROLE_CREATE": "auth:role:create",
        "AUTH_ROLE_ASSIGN": "auth:role:assign",
        "AUTH_CREDENTIAL_CREATE": "auth:credential:create",
        "AUTH_CREDENTIAL_READ": "auth:credential:read",
        "AUTH_CREDENTIAL_UPDATE": "auth:credential:update",
        "AUTH_CREDENTIAL_DELETE": "auth:credential:delete",
        "AUTH_CREDENTIAL_READ_SECRET": "auth:credential:read_secret",
        "AUTH_CREDENTIAL_TYPE_CREATE": "auth:credential_type:create",
        "AUTH_CREDENTIAL_TYPE_READ": "auth:credential_type:read",
        "AUTH_CREDENTIAL_TYPE_UPDATE": "auth:credential_type:update",
        "AUTH_CREDENTIAL_TYPE_DELETE": "auth:credential_type:delete",
        "AUTH_EMAIL_SEND": "auth:email:send",
        "AUTH_EMAIL_BULK_SEND": "auth:email:bulk_send",
        "AUTH_EMAIL_READ_TEMPLATES": "auth:email:read_templates",
        "AUTH_EMAIL_READ_STATS": "auth:email:read_stats",
        "AUTH_EMAIL_READ_PROVIDERS": "auth:email:read_providers",
        "AUTH_EMAIL_READ_HEALTH": "auth:email:read_health",
        "AUTH_EMAIL_READ_LOGS": "auth:email:read_logs",
    }
    for name, value in expected.items():
        assert getattr(auth, name) == value
    assert set(auth.__all__) == set(expected)


def test_dld_and_scraping_modules():
    from shared_auth_lib.permissions import dld, scraping

    assert dld.DLD_SYNC_MANAGE == "dld:sync:manage"
    assert dld.DLD_DATASETS_UPLOAD == "dld:datasets:upload"
    assert dld.DLD_OWNERS_READ == "dld:owners:read"
    assert dld.DLD_OWNERS_CONTACT == "dld:owners:contact"
    assert dld.DLD_OWNERS_IDENTITY == "dld:owners:identity"
    assert scraping.PROPERTY_SCRAPING_CACHE_FLUSH == "property:scraping_cache:flush"
    assert set(dld.__all__) == {
        "DLD_SYNC_MANAGE",
        "DLD_DATASETS_UPLOAD",
        "DLD_OWNERS_READ",
        "DLD_OWNERS_CONTACT",
        "DLD_OWNERS_IDENTITY",
    }
    assert set(scraping.__all__) == {"PROPERTY_SCRAPING_CACHE_FLUSH"}


def test_package_root_exports_registry_and_new_constants():
    import shared_auth_lib.permissions as pkg

    assert hasattr(pkg, "ALL_PERMISSIONS")
    assert hasattr(pkg, "PermissionDef")
    assert hasattr(pkg, "permission_names")
    assert pkg.MEDIA_BILLING_READ == "media:billing:read"
    assert pkg.MEDIA_QUOTA_MANAGE == "media:quota:manage"
    assert pkg.ADMIN_WEBHOOK_REPLAY == "admin:webhook:replay"
    assert pkg.DLD_SYNC_MANAGE == "dld:sync:manage"
    assert pkg.DLD_OWNERS_READ == "dld:owners:read"
    assert pkg.PROPERTY_SCRAPING_CACHE_FLUSH == "property:scraping_cache:flush"


def test_package_all_has_no_duplicates():
    import shared_auth_lib.permissions as pkg

    assert len(pkg.__all__) == len(set(pkg.__all__))


def test_p4_new_constants_present():
    from shared_auth_lib.permissions import cms, lead, listing

    assert cms.CMS_LANDING_PAGE_PUBLISH == "cms:landing_page:publish"
    assert lead.LEAD_NOTE_DELETE == "lead:note_delete"
    assert lead.LEAD_DOCUMENT_DELETE == "lead:document_delete"
    assert lead.LEAD_MINE_POOL_ADMIN_VIEW == "lead:mine_pool_admin_read"
    assert listing.LISTING_METRICS_READ == "listing:metrics:read"
    assert "CMS_LANDING_PAGE_PUBLISH" in cms.__all__
    for name in ("LEAD_NOTE_DELETE", "LEAD_DOCUMENT_DELETE", "LEAD_MINE_POOL_ADMIN_VIEW"):
        assert name in lead.__all__
    assert "LISTING_METRICS_READ" in listing.__all__


def test_auth_constants_flat_exported_from_package_root():
    import shared_auth_lib.permissions as pkg

    assert pkg.AUTH_SYSTEM_ADMIN == "auth:system:admin"
    assert pkg.AUTH_USER_CREATE == "auth:user:create"
    assert pkg.AUTH_ROLE_ASSIGN == "auth:role:assign"
    assert pkg.AUTH_CREDENTIAL_READ_SECRET == "auth:credential:read_secret"
    assert pkg.AUTH_EMAIL_READ_LOGS == "auth:email:read_logs"
    # every auth __all__ name is reachable flat
    from shared_auth_lib.permissions import auth

    for name in auth.__all__:
        assert getattr(pkg, name) == getattr(auth, name)
