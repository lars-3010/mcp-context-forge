from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from utils.auth import require_auth, user_has_experimental_access  # assuming these exist

class ExperimentalAccessMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/experimental"):
            user = await require_auth(request)
            if not user_has_experimental_access(user):
                raise HTTPException(
                    status_code=403,
                    detail="Experimental API requires developer or platform_admin role"
                )
        return await call_next(request)
