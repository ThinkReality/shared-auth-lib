from shared_auth_lib.permissions._registry import (
    ALL_PERMISSIONS,
    PermissionDef,
    permission_names,
)


def test_registry_entries_are_permissiondef():
    assert len(ALL_PERMISSIONS) > 0
    assert all(isinstance(p, PermissionDef) for p in ALL_PERMISSIONS)


def test_registry_names_unique():
    names = [p.name for p in ALL_PERMISSIONS]
    assert len(names) == len(set(names)), "duplicate permission names in registry"


def test_registry_resource_action_derivation():
    # resource = first segment; action = remaining segments joined with "_"
    for p in ALL_PERMISSIONS:
        first, _, rest = p.name.partition(":")
        assert p.resource == first
        assert p.action == rest.replace(":", "_")
        assert p.description, f"missing description for {p.name}"


def test_registry_covers_key_scopes():
    names = permission_names()
    for required in [
        "auth:role:create",
        "auth:role:assign",
        "auth:user:create",
        "auth:user:manage",  # bootstrap
        "media:upload",
        "media:read",
        "media:update",
        "media:delete",
        "media:billing:read",
        "media:usage:read",
        "media:quota:read",
        "media:quota:manage",
        "cms:landing_page:publish",
        "lead:read",
        "lead:create",
        "lead:update",
        "lead:delete",
        "lead:assign",
        "lead:claim",
        "lead:note_delete",
        "lead:document_delete",
        "lead:mine_pool_admin_read",
        "admin:read",
        "admin:webhook:replay",
        "dld:sync:manage",
        "dld:datasets:upload",
        "dld:owners:read",
        "dld:owners:contact",
        "dld:owners:identity",
        "property:scraping_cache:flush",
        "finance:expenses:read",
        "hr:attendance_read",
        "recruitment:posting:create",
        "listing:metrics:read",
    ]:
        assert required in names, f"{required} missing from ALL_PERMISSIONS"


def test_every_exported_constant_is_in_registry():
    # Every string value exported by the domain modules must have a registry entry.
    import shared_auth_lib.permissions as pkg

    names = permission_names()
    for value in pkg.__all__:
        const = getattr(pkg, value)
        if not isinstance(const, str):
            continue  # registry helpers (ALL_PERMISSIONS/PermissionDef/permission_names)
        assert const in names, (
            f"{value} ({const}) exported but not in ALL_PERMISSIONS"
        )
