import httpx
from tr_shared.contracts.db_pool import (
    DB_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_POOL_TIMEOUT_SECONDS,
)

from shared_auth_lib.services.auth_context_client import (
    AUTH_CONTEXT_REQUEST_TIMEOUT_SECONDS,
    AuthContextClient,
)
from tests.crm_core_stub import CRM_CORE_URL


def test_crm_core_can_fail_inside_the_auth_budget():
    crm_core_worst_case = DEFAULT_POOL_TIMEOUT_SECONDS + DB_CONNECT_TIMEOUT_SECONDS
    assert crm_core_worst_case < AUTH_CONTEXT_REQUEST_TIMEOUT_SECONDS


async def test_the_client_is_bound_by_the_budget():
    client = AuthContextClient(crm_core_url=CRM_CORE_URL, service_token="t")
    try:
        budget = httpx.Timeout(AUTH_CONTEXT_REQUEST_TIMEOUT_SECONDS)
        assert client._client.timeout == budget
    finally:
        await client.close()
