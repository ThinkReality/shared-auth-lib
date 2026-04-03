# shared-auth-lib

Shared authorization library for ThinkRealty microservices. Provides HMAC gateway signature verification, identity header extraction, AuthContext resolution from CRM-backend, and FastAPI authorization dependencies.

## Installation

```bash
pip install -e /path/to/shared-auth-lib
```

Or in a service's `requirements.txt`:

```
shared-auth-lib @ file:///path/to/shared-auth-lib
```

## Environment Variables

Each downstream service must set these:

| Variable | Required | Default | Description |
|---|---|---|---|
| `AUTH_LIB_GATEWAY_SIGNING_SECRET` | Yes | - | HMAC shared secret (must match gateway) |
| `AUTH_LIB_CRM_BACKEND_URL` | No | `http://crm-backend:8000` | CRM-backend base URL |
| `AUTH_LIB_SERVICE_TOKEN` | No | `""` | Service token for internal API calls |
| `AUTH_LIB_ENVIRONMENT` | No | `development` | Environment name |
| `AUTH_LIB_GATEWAY_TIMESTAMP_TOLERANCE` | No | `30` | Max age (seconds) for gateway timestamps |

## Integration Guide

### 1. Add Middleware (in `main.py`)

```python
from shared_auth_lib import (
    GatewayHMACMiddleware,
    IdentityExtractionMiddleware,
    AuthContextClient,
    init_auth_context_client,
)
from shared_auth_lib.config import get_settings

settings = get_settings()

# During app startup (lifespan):
client = AuthContextClient(
    crm_backend_url=settings.CRM_BACKEND_URL,
    service_token=settings.SERVICE_TOKEN,
)
init_auth_context_client(client)

# Middleware order matters: HMAC first, then identity extraction
app.add_middleware(IdentityExtractionMiddleware)
app.add_middleware(
    GatewayHMACMiddleware,
    secret=settings.GATEWAY_SIGNING_SECRET,
)
```

### 2. Protect Routes

```python
from fastapi import Depends
from shared_auth_lib import (
    AuthContext,
    require_auth,
    require_permission,
    require_role,
    require_any_role,
    optional_auth,
)

@router.get("/listings")
async def list_listings(
    auth: AuthContext = Depends(require_auth),
):
    # auth.user_id, auth.tenant_id, auth.roles, auth.permissions
    ...

@router.delete("/listings/{id}")
async def delete_listing(
    auth: AuthContext = Depends(require_permission("listing:delete")),
):
    ...

@router.get("/admin/users")
async def admin_users(
    auth: AuthContext = Depends(require_role("ADMIN")),
):
    ...

@router.get("/public/featured")
async def featured(
    auth: AuthContext | None = Depends(optional_auth),
):
    ...
```

### 3. Shutdown

```python
# During app shutdown:
await client.close()
```

## Architecture

```
Client -> API Gateway -> [HMAC Sign] -> Downstream Service
                                            |
                                    GatewayHMACMiddleware (verify signature)
                                            |
                                    IdentityExtractionMiddleware (extract headers)
                                            |
                                    require_auth dependency
                                            |
                                    AuthContextClient -> CRM-backend /internal/auth-context/{id}
                                            |
                                    AuthContext (roles, permissions, tenant_id)
                                            |
                                    require_permission / require_role
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Package Structure

```
shared_auth_lib/
    __init__.py              # Public API re-exports
    config.py                # AuthLibSettings (pydantic-settings)
    exceptions.py            # Library-specific exceptions
    logging.py               # Structured logging (structlog)
    models/
        auth_context.py      # AuthContext, GatewayIdentityHeaders
    middleware/
        hmac_middleware.py    # GatewayHMACMiddleware
        identity_middleware.py # IdentityExtractionMiddleware
    services/
        hmac_verifier.py     # compute_signature, verify_signature
        auth_context_client.py # CRM-backend API client
    dependencies/
        auth_dependencies.py # require_auth, require_permission, etc.
```
