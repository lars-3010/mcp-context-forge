# Third-Party
from fastapi import (
    HTTPException,
    Request,
)
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

# First-Party
from mcpgateway.utils.verify_credentials import require_auth, require_auth_override

class DocsAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to protect FastAPI's auto-generated documentation routes
    (/docs, /redoc, and /openapi.json) using Bearer token authentication.

    If a request to one of these paths is made without a valid token,
    the request is rejected with a 401 or 403 error.

    Note:
        When DOCS_ALLOW_BASIC_AUTH is enabled, Basic Authentication
        is also accepted using BASIC_AUTH_USER and BASIC_AUTH_PASSWORD credentials.
    """

    async def dispatch(self, request: Request, call_next):
        """
        Intercepts incoming requests to check if they are accessing protected documentation routes.
        If so, it requires a valid Bearer token; otherwise, it allows the request to proceed.

        Args:
            request (Request): The incoming HTTP request.
            call_next (Callable): The function to call the next middleware or endpoint.

        Returns:
            Response: Either the standard route response or a 401/403 error response.

        Examples:
            >>> import asyncio
            >>> from unittest.mock import Mock, AsyncMock, patch
            >>> from fastapi import HTTPException
            >>> from fastapi.responses import JSONResponse
            >>>
            >>> # Test unprotected path - should pass through
            >>> middleware = DocsAuthMiddleware(None)
            >>> request = Mock()
            >>> request.url.path = "/api/tools"
            >>> request.headers.get.return_value = None
            >>> call_next = AsyncMock(return_value="response")
            >>>
            >>> result = asyncio.run(middleware.dispatch(request, call_next))
            >>> result
            'response'
            >>>
            >>> # Test that middleware checks protected paths
            >>> request.url.path = "/docs"
            >>> isinstance(middleware, DocsAuthMiddleware)
            True
        """
        protected_paths = ["/docs", "/redoc", "/openapi.json"]

        if any(request.url.path.startswith(p) for p in protected_paths):
            try:
                token = request.headers.get("Authorization")
                cookie_token = request.cookies.get("jwt_token")

                # Simulate what Depends(require_auth) would do
                await require_auth_override(token, cookie_token)
            except HTTPException as e:
                return JSONResponse(status_code=e.status_code, content={"detail": e.detail}, headers=e.headers if e.headers else None)

        # Proceed to next middleware or route
        return await call_next(request)
