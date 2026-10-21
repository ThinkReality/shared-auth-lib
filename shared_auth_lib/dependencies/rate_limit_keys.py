from fastapi import Depends, Request

from tr_shared.client_ip import client_ip
from shared_auth_lib.dependencies.auth_dependencies import require_auth
from shared_auth_lib.models.auth_context import AuthContext


def user_rate_limit_key(auth: AuthContext = Depends(require_auth)) -> str:
    return f"user:{auth.user_id}"


def client_rate_limit_key(request: Request) -> str:
    return f"ip:{client_ip(request)}"
