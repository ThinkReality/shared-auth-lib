"""Task feature permission constants. Scheme: {feature}:{action} (D-PERMSCHEME).

The canonical permission vocabulary for the task feature. Services use these
constants, never inline permission-string literals. New per-feature modules
follow this exact shape + the conformance test in tests/test_permissions.py.
"""

TASK_VIEW = "task:view"
TASK_CREATE = "task:create"
TASK_EDIT = "task:edit"
TASK_DELETE = "task:delete"
TASK_ASSIGN = "task:assign"

__all__ = [
    "TASK_ASSIGN",
    "TASK_CREATE",
    "TASK_DELETE",
    "TASK_EDIT",
    "TASK_VIEW",
]
