import os

from tr_shared.config.env_audit import declared_env_keys_by_sensitivity
from tr_shared.testing.config import POLICY_ENV

from shared_auth_lib.config import AuthLibSettings

AUTH_LIB_POLICY_KEYS = {key for key in POLICY_ENV if key.startswith("AUTH_LIB_")}


def test_every_auth_lib_policy_key_is_an_auth_lib_settings_field() -> None:
    declared, _ = declared_env_keys_by_sensitivity(AuthLibSettings)
    assert AUTH_LIB_POLICY_KEYS
    assert AUTH_LIB_POLICY_KEYS <= declared


def test_the_suite_runs_on_the_plugin_policy_values() -> None:
    assert {key: os.environ.get(key) for key in POLICY_ENV} == POLICY_ENV
