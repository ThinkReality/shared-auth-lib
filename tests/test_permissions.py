# tests/test_permissions.py
import importlib
import pkgutil
import re

import shared_auth_lib.permissions as permissions_pkg
from tr_shared.contracts.taxonomy import Feature

# The locked action vocabulary (D-PERMSCHEME). Every permission is {feature}:{action}
# where feature is a Feature-spine member and action is one of these eight.
ALLOWED_ACTIONS = {
    "view", "create", "edit", "delete", "export",
    "sync", "approve", "assign",
}
_FEATURES = {f.value for f in Feature}
_SCHEME = re.compile(r"^[a-z]+:[a-z_]+$")


def _iter_permission_modules():
    for info in pkgutil.iter_modules(permissions_pkg.__path__):
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
            assert _SCHEME.match(perm), f"{perm!r} is not '{{feature}}:{{action}}'"
            feature, action = perm.split(":")
            assert feature in _FEATURES, (
                f"{perm!r} prefix {feature!r} is not a Feature-spine member "
                f"({sorted(_FEATURES)})"
            )
            assert action in ALLOWED_ACTIONS, (
                f"{perm!r} action {action!r} not in the locked set {sorted(ALLOWED_ACTIONS)}"
            )
    assert seen, "permission modules declared no constants"


def test_task_constants_importable_from_permissions_package():
    from shared_auth_lib.permissions import TASK_ASSIGN, TASK_VIEW

    assert TASK_VIEW == "task:view"
    assert TASK_ASSIGN == "task:assign"
