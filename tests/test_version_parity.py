"""Guard: __version__ and pyproject [project].version must never drift."""

import tomllib
from pathlib import Path

import shared_auth_lib


def test_version_matches_pyproject():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert shared_auth_lib.__version__ == data["project"]["version"]


def test_permission_modules_importable():
    from shared_auth_lib.permissions import (  # noqa: F401
        FINANCE_VIEW,
        HR_ATTENDANCE_READ,
        LEAD_VIEW,
        LISTING_VIEW,
        MEDIA_UPLOAD,
    )
