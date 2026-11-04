"""Startup checks a service runs against its own entry point, in a subprocess."""

import os
import subprocess
import sys
from pathlib import Path

from shared_auth_lib.config import DEV_BYPASS_REFUSAL

_TIMEOUT_SECONDS = 10


def assert_app_refuses_dev_bypass(repo_root: Path) -> None:
    """``import app.main`` with the bypass on exits non-zero with shared-auth-lib's refusal.

    Runs in ``repo_root`` with the test's environment, whose ``ENVIRONMENT`` is ``test``.
    """
    result = subprocess.run(
        [sys.executable, "-c", "import app.main"],
        cwd=repo_root,
        env={**os.environ, "AUTH_LIB_DEV_MODE_BYPASS": "true"},
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
    )
    assert result.returncode != 0 and DEV_BYPASS_REFUSAL in result.stderr, (
        f"python -c import app.main: exit {result.returncode}, expected {DEV_BYPASS_REFUSAL!r}\n"
        f"{result.stderr[-2000:]}"
    )
