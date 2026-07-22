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
    "view", "create", "edit", "delete", "export",
    "sync", "approve", "assign",
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
        "SYSTEM_ADMIN": "system:admin",
        "AUDIT_READ": "audit:read",
        "USER_CREATE": "user:create",
        "USER_MANAGE": "user:manage",
        "USER_SUSPEND": "user:suspend",
        "ROLE_CREATE": "role:create",
        "ROLE_ASSIGN": "role:assign",
        "CREDENTIAL_CREATE": "credential:create",
        "CREDENTIAL_READ": "credential:read",
        "CREDENTIAL_UPDATE": "credential:update",
        "CREDENTIAL_DELETE": "credential:delete",
        "CREDENTIAL_READ_SECRET": "credential:read_secret",
        "CREDENTIAL_TYPE_CREATE": "credential_type:create",
        "CREDENTIAL_TYPE_READ": "credential_type:read",
        "CREDENTIAL_TYPE_UPDATE": "credential_type:update",
        "CREDENTIAL_TYPE_DELETE": "credential_type:delete",
        "EMAIL_SEND": "email:send",
        "EMAIL_BULK_SEND": "email:bulk_send",
        "EMAIL_READ_TEMPLATES": "email:read_templates",
        "EMAIL_READ_STATS": "email:read_stats",
        "EMAIL_READ_PROVIDERS": "email:read_providers",
        "EMAIL_READ_HEALTH": "email:read_health",
        "EMAIL_READ_LOGS": "email:read_logs",
    }
    for name, value in expected.items():
        assert getattr(auth, name) == value
    assert set(auth.__all__) == set(expected)


def test_dld_and_scraping_modules():
    from shared_auth_lib.permissions import dld, scraping

    assert dld.DLD_SYNC_MANAGE == "dld:sync:manage"
    assert dld.DLD_DATASETS_UPLOAD == "dld:datasets:upload"
    assert scraping.SCRAPING_CACHE_FLUSH == "scraping:cache:flush"
    assert set(dld.__all__) == {"DLD_SYNC_MANAGE", "DLD_DATASETS_UPLOAD"}
    assert set(scraping.__all__) == {"SCRAPING_CACHE_FLUSH"}
