from pathlib import Path

from tr_shared.testing.guards import assert_no_dotenv_loading

SAL_REPO = Path(__file__).resolve().parents[1]


def test_the_lib_reads_no_dotenv_file() -> None:
    assert_no_dotenv_loading(SAL_REPO)
