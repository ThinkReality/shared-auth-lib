# tests/test_auth_context_field_freeze.py
from shared_auth_lib.models.auth_context import AuthContext

# The 12 frozen wire fields as of 2026-07-26. Do NOT change this set until the
# node-centric RBAC overhaul (doc 5) is scheduled — it is a coordinated hard-cut
# across gateway + lib + all services.
#
# `role_hierarchy` was dropped in v0.16.0 (was 13 fields). It existed solely to
# feed `AuthContext.has_role`, which widened cross-tenant scope gates via
# inherited roles; both were removed. Dropping it needed no coordinated rollout:
# AuthContext uses Pydantic's default `extra="ignore"`, so a producer still
# sending the field is tolerated, and a consumer on an older lib falls back to
# the field's default — compatible in both directions, in any deploy order.
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
}


def test_auth_context_wire_fields_are_frozen():
    assert set(AuthContext.model_fields.keys()) == FROZEN_FIELDS
