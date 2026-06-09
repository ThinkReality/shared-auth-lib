# tests/test_permissions.py
import re

from shared_auth_lib.permissions import task as task_perms

ALLOWED_ACTIONS = {
    "view", "create", "edit", "delete", "export",
    "sync", "approve", "assign",
}
_SCHEME = re.compile(r"^[a-z]+:[a-z_]+$")


def _constants(module) -> list[str]:
    return [getattr(module, name) for name in module.__all__]


def test_task_permissions_follow_feature_action_scheme():
    perms = _constants(task_perms)
    assert perms  # module is not empty
    for perm in perms:
        assert _SCHEME.match(perm), f"{perm!r} is not '{{feature}}:{{action}}'"
        feature, action = perm.split(":")
        assert feature == "task", f"{perm!r} prefix must be the feature 'task'"
        assert action in ALLOWED_ACTIONS, f"{action!r} is not an allowed action"


def test_task_constants_importable_from_permissions_package():
    from shared_auth_lib.permissions import TASK_ASSIGN, TASK_VIEW

    assert TASK_VIEW == "task:view"
    assert TASK_ASSIGN == "task:assign"
