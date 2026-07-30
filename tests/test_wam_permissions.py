from shared_auth_lib.permissions import (
    WAM_BROADCAST_READ,
    WAM_BROADCAST_SEND,
    WAM_SESSION_MANAGE,
)
from shared_auth_lib.permissions._registry import ALL_PERMISSIONS


def test_wam_permissions_are_registered_with_derived_fields():
    """The constants exist, are registered, and _d() derived the fields the
    catalog sync writes. One test, because the registry's own conformance
    sweep already covers naming and the exported-constant round trip."""
    by_name = {p.name: p for p in ALL_PERMISSIONS}

    for constant in (WAM_SESSION_MANAGE, WAM_BROADCAST_READ, WAM_BROADCAST_SEND):
        assert constant in by_name, f"{constant} missing from ALL_PERMISSIONS"
        assert by_name[constant].resource == "wam"
        assert by_name[constant].description

    assert by_name[WAM_SESSION_MANAGE].action == "session_manage"
    assert by_name[WAM_BROADCAST_SEND].action == "broadcast_send"
