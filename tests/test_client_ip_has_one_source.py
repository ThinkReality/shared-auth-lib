from pathlib import Path

from tr_shared.testing import assert_no_local_client_ip_derivation

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "shared_auth_lib"


def test_shared_auth_lib_never_derives_the_client_ip_itself() -> None:
    assert_no_local_client_ip_derivation(PACKAGE_ROOT)
