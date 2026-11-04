from pathlib import Path

from tr_shared.testing.env_contract import assert_settings_are_env_safe

SAL_REPO = Path(__file__).resolve().parents[1]


def test_the_libs_settings_are_env_safe() -> None:
    assert_settings_are_env_safe(SAL_REPO, package="shared_auth_lib")
