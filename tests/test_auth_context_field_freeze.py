# tests/test_auth_context_field_freeze.py
from shared_auth_lib.models.auth_context import AuthContext

# The 13 frozen wire fields as of 2026-06-08. Do NOT change this set until the
# node-centric RBAC overhaul (doc 5) is scheduled — it is a coordinated hard-cut
# across gateway + lib + all services.
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
    "role_hierarchy",
    "correlation_id",
    "auth_provider",
}


def test_auth_context_wire_fields_are_frozen():
    assert set(AuthContext.model_fields.keys()) == FROZEN_FIELDS
