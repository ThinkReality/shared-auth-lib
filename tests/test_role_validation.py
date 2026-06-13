"""L2.1: require_role / require_any_role validate against PlatformRole at
dependency-construction time (router registration), not at request time."""

import pytest

from shared_auth_lib.constants.roles import PlatformRole
from shared_auth_lib.dependencies.auth_dependencies import (
    require_any_role,
    require_role,
)


def test_require_role_accepts_platformrole():
    require_role(PlatformRole.ADMIN)


def test_require_role_accepts_valid_string():
    require_role("ADMIN")


def test_require_role_rejects_unknown_string():
    with pytest.raises(ValueError, match="FAKE"):
        require_role("FAKE")


def test_require_any_role_accepts_mixed():
    require_any_role([PlatformRole.ADMIN, "MANAGER"])


def test_require_any_role_rejects_bad_entry():
    with pytest.raises(ValueError, match="NOT_A_ROLE"):
        require_any_role(["ADMIN", "NOT_A_ROLE"])
