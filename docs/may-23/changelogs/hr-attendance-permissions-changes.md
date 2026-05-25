# HR Attendance Permission Contract Changes - 2026-05-23

Author: ThinkRealty backend team

Branch: `feat/hr-attendance-integration-may23`

Target: `main`

Scope: Shared HR attendance authorization vocabulary.

## Change

The shared authentication library now exports these canonical HR attendance permissions:

```python
ATTENDANCE_READ = "attendance:read"
ATTENDANCE_EXPORT = "attendance:export"
ATTENDANCE_SYNC = "attendance:sync"
ATTENDANCE_MANUAL_CREATE = "attendance:manual_create"
ATTENDANCE_APPROVE = "attendance:approve"
ATTENDANCE_EXCEPTIONS_MANAGE = "attendance:exceptions_manage"
```

## Reason

The HR API, CRM role grants, and API gateway route enforcement must all refer to one authorization vocabulary.

## History Exclusion

This feature branch is based directly on `origin/main`. Previously present local merge/dependency commits are not part of this HR attendance PR.

## Verification

- `uv run ruff check shared_auth_lib tests` passed.
- `uv run pytest tests -q --no-cov` passed: `96 passed`.
