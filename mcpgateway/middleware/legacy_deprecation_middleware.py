# # First-party
# # Third-Party
# from fastapi import Request
# from starlette.middleware.base import BaseHTTPMiddleware

# # First-Party
# from mcpgateway.services.logging_service import LoggingService

# # Initialize logging service first
# logging_service = LoggingService()
# logger = logging_service.get_logger("prompt routes")


# def is_legacy_path(path: str) -> bool:
#     """
#     Returns True if the given path is a legacy (unversioned) API endpoint.

#     Legacy paths:
#     - Do NOT start with /v1/ or /experimental/
#     - Are not static, docs, or root paths

#     Examples:
#         /tools           -> True
#         /v1/tools        -> False
#         /experimental/foo -> False
#         /openapi.json    -> False
#         /                -> False
#     """
#     # Normalize empty path
#     if not path or path == "/" or path.startswith("/docs") or path.startswith("/openapi"):
#         return False

#     # Check versioned and experimental prefixes
#     if path.startswith("/v1/") or path.startswith("/experimental/"):
#         return False

#     # Could add further checks for /admin, /static, etc. as needed
#     return True


# class LegacyDeprecationMiddleware(BaseHTTPMiddleware):

#     def __init__(self, app):
#         super().__init__(app)
    
#     async def dispatch(self, request: Request, call_next):
#         if is_legacy_path(request.url.path):
#             logger.warning(f"DEPRECATED: {request.url.path} -> /v1{request.url.path}")

#             response = await call_next(request)
#             response.headers.update(
#                 {
#                     "X-API-Deprecated": "true",
#                     "X-API-Removal-Version": "0.7.0",
#                     "X-API-Migration-Guide": "/docs/migration-urgent",
#                     "Warning": '299 - "This API version will be removed in 0.7.0. Migrate immediately."',
#                 }
#             )
#             return response

#         # Non-legacy path — still pass along to the next handler
#         return await call_next(request)

#     # async def dispatch(self, request: Request, call_next):
#     #     if is_legacy_path(request.url.path):
#     #         # LOUD deprecation warnings
#     #         logger.warning(f"DEPRECATED: {request.url.path} -> /v1{request.url.path}")

#     #         response = await call_next(request)
#     #         response.headers.update(
#     #             {
#     #                 "X-API-Deprecated": "true",
#     #                 "X-API-Removal-Version": "0.7.0",
#     #                 "X-API-Migration-Guide": "/docs/migration-urgent",
#     #                 "Warning": '299 - "This API version will be removed in 0.7.0. Migrate immediately."',
#     #             }
#     #         )
#     #         return response

# # Third-Party
# from fastapi import Request
# from starlette.middleware.base import BaseHTTPMiddleware

# # First-Party
# from mcpgateway.services.logging_service import LoggingService

# # Initialize logging service first
# logging_service = LoggingService()
# logger = logging_service.get_logger("legacy routes")


# def is_legacy_path(path: str) -> bool:
#     """
#     Check if the given path is a legacy (unversioned) API endpoint.
#     Legacy paths:
#     - Do NOT start with /v1/ or /experimental/
#     - Are not static, docs, openapi, or root paths
#     """
#     if not path or path == "/" or path.startswith("/docs") or path.startswith("/openapi"):
#         return False
#     if path.startswith("/v1/") or path.startswith("/experimental/"):
#         return False
#     return True


# class LegacyDeprecationMiddleware(BaseHTTPMiddleware):
#     def __init__(self, app):
#         super().__init__(app)

#     async def dispatch(self, request: Request, call_next):
#         if is_legacy_path(request.url.path):
#             # LOUD warning in logs
#             logger.warning(
#                 f"DEPRECATED API CALL: {request.url.path} "
#                 f"-> Suggested migration: /v1{request.url.path}"
#             )

#             response = await call_next(request)

#             # Add deprecation headers
#             response.headers.update({
#                 "X-API-Deprecated": "true",
#                 "X-API-Removal-Version": "0.7.0",
#                 "X-API-Migration-Guide": "/docs/migration-urgent",
#                 "Warning": '299 - "This API version will be removed in 0.7.0. Migrate immediately."'
#             })
#             return response

#         # Not legacy — pass through
#         return await call_next(request)

# Third-Party
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse

# First-Party
from mcpgateway.services.logging_service import LoggingService

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("legacy routes")


def is_legacy_path(path: str) -> bool:
    """
    Check if the given path is a legacy (unversioned) API endpoint.
    Legacy paths:
    - Do NOT start with /v1/ or /experimental/
    - Are not static, docs, openapi, admin, health, ready, or root paths
    """
    if not path or path == "/":
        return False
    if path.startswith(("/docs", "/openapi", "/redoc", "/static", "/admin", "/health", "/ready", "/version")):
        return False
    if path.startswith(("/v1/", "/experimental/")):
        return False
    # Check for API endpoints that should be versioned
    api_endpoints = ["/tools", "/resources", "/prompts", "/servers", "/gateways", "/roots", "/protocol", "/metrics", "/rpc"]
    return any(path.startswith(endpoint) for endpoint in api_endpoints)


class LegacyDeprecationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if is_legacy_path(path):
            # LOUD warning in logs
            logger.warning(
                f"DEPRECATED API CALL: {path} "
                f"-> Suggested migration: /v1{path}"
            )

            # Don't rewrite path since root routes are now directly mounted
            response: Response = await call_next(request)

            # Add deprecation headers
            response.headers.update({
                "X-API-Deprecated": "true",
                "X-API-Removal-Version": "0.7.0",
                "X-API-Migration-Guide": "/docs/migration-urgent",
                "Warning": '299 - "This API version will be removed in 0.7.0. Migrate immediately."'
            })
            return response

        # Not legacy — pass through
        return await call_next(request)

