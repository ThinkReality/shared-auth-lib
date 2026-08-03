# tests/test_auth_context_field_freeze.py
from shared_auth_lib.models.auth_context import AuthContext

# The 13 frozen wire fields as of 2026-08-03. Do NOT REMOVE OR RENAME any entry
# in this set until the node-centric RBAC overhaul (doc 5) is scheduled — that is
# a coordinated hard-cut across gateway + lib + all services.
#
# ADDING a field is not that cut, and this set has now been amended twice on that
# basis. `role_hierarchy` was dropped in v0.16.0 (13 -> 12) and `enabled_modules`
# added in v0.26.0 (12 -> 13). Both were safe for the same reason: AuthContext
# uses Pydantic's default `extra="ignore"`, so a producer sending a field the
# consumer does not know is tolerated, and a consumer on an older lib falls back
# to the field's default — compatible in both directions, in any deploy order.
#
# The rule this set enforces is therefore: removals and renames need a scheduled
# coordinated cut; additions need a deliberate amendment here, like this one.
FROZEN_FIELDS = {
    "external_auth_id",
    "user_id",
    "email",
    "first_name",
    "last_name",
    "tenant_id",
    "roles",
    "permissions",
    "is_active",
    "is_suspended",
    "correlation_id",
    "auth_provider",
    "enabled_modules",
}


def test_auth_context_wire_fields_are_frozen():
    assert set(AuthContext.model_fields.keys()) == FROZEN_FIELDS
