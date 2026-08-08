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
# Row-visibility bypass for GET /tasks: without it, a caller sees only tasks
# they are assigned_to, created_by, assigned_by, or a co-assignee on — never
# a route gate, always a result-filtering decision. See tr-crm-core
# app/modules/task/repositories/task_repository.py.
TASK_READ_ALL = "task:read_all"

__all__ = [
    "TASK_ASSIGN",
    "TASK_CREATE",
    "TASK_DELETE",
    "TASK_EDIT",
    "TASK_READ_ALL",
    "TASK_VIEW",
]
