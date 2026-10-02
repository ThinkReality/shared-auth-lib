import httpx

from shared_auth_lib.services.auth_context_client import AuthContextClient

CRM_CORE_URL = "http://tr-crm-core:8000"


def auth_context_client(
    transport: httpx.MockTransport, **options: int
) -> AuthContextClient:
    client = AuthContextClient(
        crm_core_url=CRM_CORE_URL, service_token="test-token", **options
    )
    client._client = httpx.AsyncClient(base_url=CRM_CORE_URL, transport=transport)
    return client
