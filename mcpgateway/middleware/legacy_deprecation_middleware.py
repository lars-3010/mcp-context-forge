#First-party
from mcpgateway.services.logging_service import LoggingService

# Third-Party
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("prompt routes")


def is_legacy_path(path: str) -> bool:
    """
    Returns True if the given path is a legacy (unversioned) API endpoint.

    Legacy paths:
    - Do NOT start with /v1/ or /experimental/
    - Are not static, docs, or root paths

    Examples:
        /tools           -> True
        /v1/tools        -> False
        /experimental/foo -> False
        /openapi.json    -> False
        /                -> False
    """
    # Normalize empty path
    if not path or path == "/" or path.startswith("/docs") or path.startswith("/openapi"):
        return False

    # Check versioned and experimental prefixes
    if path.startswith("/v1/") or path.startswith("/experimental/"):
        return False

    # Could add further checks for /admin, /static, etc. as needed
    return True

class LegacyDeprecationMiddleware(BaseHTTPMiddleware):

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        if is_legacy_path(request.url.path):
            # LOUD deprecation warnings
            logger.warning(f"DEPRECATED: {request.url.path} -> /v1{request.url.path}")
            
            response = await call_next(request)
            response.headers.update({
                "X-API-Deprecated": "true",
                "X-API-Removal-Version": "0.7.0", 
                "X-API-Migration-Guide": "/docs/migration-urgent",
                "Warning": "299 - \"This API version will be removed in 0.7.0. Migrate immediately.\""
            })
            return response