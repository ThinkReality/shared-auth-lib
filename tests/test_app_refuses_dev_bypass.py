"""A service's ``import app.main`` must refuse the dev bypass outside development."""

from pathlib import Path

import pytest

from shared_auth_lib.testing import assert_app_refuses_dev_bypass


def _service(root: Path, main: str) -> Path:
    (root / "app").mkdir()
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "main.py").write_text(main)
    return root


def test_an_app_that_builds_the_settings_at_import_passes(tmp_path: Path) -> None:
    main = "from shared_auth_lib.config import get_settings\n\nget_settings()\n"
    assert_app_refuses_dev_bypass(_service(tmp_path, main))


def test_an_app_that_never_builds_the_settings_fails(tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="import app.main: exit 0"):
        assert_app_refuses_dev_bypass(_service(tmp_path, ""))


def test_an_app_that_fails_for_another_reason_fails(tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="import app.main: exit 1"):
        assert_app_refuses_dev_bypass(
            _service(tmp_path, "raise RuntimeError('no database')\n")
        )
