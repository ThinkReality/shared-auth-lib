"""Authorization decisions raise typed exceptions, never a raw ``HTTPException``.

Two authorization systems existed here and disagreed. ``require_capability``
raised ``AuthorizationError`` — canonical envelope, error code, traceable in logs
— while ``require_permission`` next door raised a bare ``HTTPException``, whose
handler stamps ``HTTP_403`` and loses the reason to a free-text string. Every
``require_permission`` denial in the fleet violated the Response Shapes rule for
as long as both shapes were allowed to coexist.

This guard encodes the rule, not the six sites that were converted: a new
dependency reaching for ``HTTPException`` fails here immediately, by file and
line. That is the only thing that stops the split from reopening.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_LIB_ROOT = Path(__file__).resolve().parents[1] / "shared_auth_lib"

# Authorization decisions live here. Both directories are entirely about deciding
# whether a caller may proceed, so neither has any business raising an untyped
# error. Middleware is deliberately excluded: it runs outside the
# exception-handler chain, cannot raise into it, and builds its canonical body
# through ``build_error_envelope`` instead — see ``hmac_middleware._rejected``.
_GUARDED_DIRS = ("dependencies", "authz")


def _guarded_files() -> list[Path]:
    return sorted(
        path
        for directory in _GUARDED_DIRS
        for path in (_LIB_ROOT / directory).rglob("*.py")
    )


def test_the_guard_actually_looks_at_something() -> None:
    """A guard over an empty file list passes forever and proves nothing."""
    files = _guarded_files()

    assert files, f"no Python files found under {_GUARDED_DIRS} — the guard is inert"


@pytest.mark.parametrize("path", _guarded_files(), ids=lambda p: p.name)
def test_no_raw_httpexception_raised(path: Path) -> None:
    tree = ast.parse(path.read_text(), filename=str(path))

    offenders = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "HTTPException"
    ]

    assert not offenders, (
        f"{path.name} raises a raw HTTPException at line(s) "
        f"{', '.join(map(str, offenders))}. Raise a tr_shared.exceptions type "
        f"(AuthenticationError / AuthorizationError) with an AUTHLIB_AUTH_NNN "
        f"code so the response carries the canonical envelope."
    )
