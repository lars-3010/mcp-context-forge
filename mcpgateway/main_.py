# -*- coding: utf-8 -*-
"""
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

MCP Gateway - Main FastAPI Application.

This module defines the core FastAPI application for the Model Context Protocol (MCP) Gateway.
It serves as the entry point for handling all HTTP and WebSocket traffic.

Features and Responsibilities:
- Initializes and orchestrates services for tools, resources, prompts, servers, gateways, and roots.
- Supports full MCP protocol operations: initialize, ping, notify, complete, and sample.
- Integrates authentication (JWT and basic), CORS, caching, and middleware.
- Serves a rich Admin UI for managing gateway entities via HTMX-based frontend.
- Exposes routes for JSON-RPC, SSE, and WebSocket transports.
- Manages application lifecycle including startup and graceful shutdown of all services.

Structure:
- Declares routers for MCP protocol operations and administration.
- Registers dependencies (e.g., DB sessions, auth handlers).
- Applies middleware including custom documentation protection.
- Configures resource caching and session registry using pluggable backends.
- Provides OpenAPI metadata and redirect handling depending on UI feature flags.
"""

# Standard
import asyncio
from contextlib import asynccontextmanager
import json
import logging
from typing import Any, AsyncIterator, Dict, List, Optional, Union
from urllib.parse import urlparse, urlunparse

# Third-Party
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    status,
)

from fastapi.exception_handlers import request_validation_exception_handler as fastapi_default_validation_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

# First-Party
from mcpgateway import __version__
from mcpgateway.admin import admin_router
from mcpgateway.bootstrap_db import main as bootstrap_db
from mcpgateway.cache import ResourceCache, SessionRegistry
from mcpgateway.config import jsonpath_modifier, settings
from mcpgateway.db import refresh_slugs_on_startup, SessionLocal, get_db
from mcpgateway.handlers.sampling import SamplingHandler
from mcpgateway.plugins import PluginManager

from mcpgateway.services.completion_service import CompletionService
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import ServerService
from mcpgateway.services.tag_service import TagService
from mcpgateway.services.tool_service import ToolService
from mcpgateway.transports.sse_transport import SSETransport
from mcpgateway.transports.streamablehttp_transport import (
    SessionManagerWrapper,
    streamable_http_auth,
)
from mcpgateway.utils.db_isready import wait_for_db_ready
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.redis_isready import wait_for_redis_ready
from mcpgateway.utils.retry_manager import ResilientHttpClient
from mcpgateway.utils.verify_credentials import require_auth, require_auth_override

# middleware imports
from mcpgateway.middleware.docs_auth_middleware import DocsAuthMiddleware
from mcpgateway.middleware.mcp_path_rewrite_middleware import MCPPathRewriteMiddleware

# Import the admin routes from the new module
from mcpgateway.version import router as version_router

# from v1 routes
from mcpgateway.routers.setup_routes import (
    setup_v1_routes,
    setup_experimental_routes,
    setup_legacy_deprecation_routes,
)


# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("mcpgateway")

# Configure root logger level
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Wait for database to be ready before creating tables
wait_for_db_ready(max_tries=int(settings.db_max_retries), interval=int(settings.db_retry_interval_ms) / 1000, sync=True)  # Converting ms to s

# Create database tables
try:
    loop = asyncio.get_running_loop()
except RuntimeError:
    asyncio.run(bootstrap_db())
else:
    loop.create_task(bootstrap_db())

# Initialize plugin manager as a singleton.
plugin_manager: PluginManager | None = PluginManager(settings.plugin_config_file) if settings.plugins_enabled else None

# Initialize services
tool_service = ToolService()
resource_service = ResourceService()
prompt_service = PromptService()
gateway_service = GatewayService()
root_service = RootService()
completion_service = CompletionService()
sampling_handler = SamplingHandler()
server_service = ServerService()
tag_service = TagService()

# Initialize session manager for Streamable HTTP transport
streamable_http_session = SessionManagerWrapper()

# Wait for redis to be ready
if settings.cache_type == "redis":
    wait_for_redis_ready(redis_url=settings.redis_url, max_retries=int(settings.redis_max_retries), retry_interval_ms=int(settings.redis_retry_interval_ms), sync=True)



# Initialize cache
resource_cache = ResourceCache(max_size=settings.resource_cache_size, ttl=settings.resource_cache_ttl)


####################
# Startup/Shutdown #
####################
@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """
    Manage the application's startup and shutdown lifecycle.

    The function initialises every core service on entry and then
    shuts them down in reverse order on exit.

    Args:
        _app (FastAPI): FastAPI app

    Yields:
        None

    Raises:
        Exception: Any unhandled error that occurs during service
            initialisation or shutdown is re-raised to the caller.
    """
    logger.info("Starting MCP Gateway services")
    try:
        if plugin_manager:
            await plugin_manager.initialize()
            logger.info(f"Plugin manager initialized with {plugin_manager.plugin_count} plugins")
        await tool_service.initialize()
        await resource_service.initialize()
        await prompt_service.initialize()
        await gateway_service.initialize()
        await root_service.initialize()
        await completion_service.initialize()
        await logging_service.initialize()
        await sampling_handler.initialize()
        await resource_cache.initialize()
        await streamable_http_session.initialize()
        refresh_slugs_on_startup()

        logger.info("All services initialized successfully")
        yield
    except Exception as e:
        logger.error(f"Error during startup: {str(e)}")
        raise
    finally:
        # Shutdown plugin manager
        if plugin_manager:
            try:
                await plugin_manager.shutdown()
                logger.info("Plugin manager shutdown complete")
            except Exception as e:
                logger.error(f"Error shutting down plugin manager: {str(e)}")
        logger.info("Shutting down MCP Gateway services")
        # await stop_streamablehttp()
        for service in [resource_cache, sampling_handler, logging_service, completion_service, root_service, gateway_service, prompt_service, resource_service, tool_service, streamable_http_session]:
            try:
                await service.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down {service.__class__.__name__}: {str(e)}")
        logger.info("Shutdown complete")


def create_app() -> FastAPI:
    # Initialize FastAPI app
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="A FastAPI-based MCP Gateway with federation support",
        root_path=settings.app_root_path,
        lifespan=lifespan,
         version="0.6.0"
    )


        # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if not settings.allowed_origins else list(settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Type", "Content-Length"],
    )


    # Add custom DocsAuthMiddleware
    app.add_middleware(DocsAuthMiddleware)

    # Add streamable HTTP middleware for /mcp routes
    app.add_middleware(MCPPathRewriteMiddleware)

    # Trust all proxies (or lock down with a list of host patterns)
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")


    # Global exceptions handlers
    @app.exception_handler(ValidationError)
    async def validation_exception_handler(_request: Request, exc: ValidationError):
        """Handle Pydantic validation errors globally.

        Intercepts ValidationError exceptions raised anywhere in the application
        and returns a properly formatted JSON error response with detailed
        validation error information.

        Args:
            _request: The FastAPI request object that triggered the validation error.
                    (Unused but required by FastAPI's exception handler interface)
            exc: The Pydantic ValidationError exception containing validation
                failure details.

        Returns:
            JSONResponse: A 422 Unprocessable Entity response with formatted
                        validation error details.

        Examples:
            >>> from pydantic import ValidationError, BaseModel
            >>> from fastapi import Request
            >>> import asyncio
            >>>
            >>> class TestModel(BaseModel):
            ...     name: str
            ...     age: int
            >>>
            >>> # Create a validation error
            >>> try:
            ...     TestModel(name="", age="invalid")
            ... except ValidationError as e:
            ...     # Test our handler
            ...     result = asyncio.run(validation_exception_handler(None, e))
            ...     result.status_code
            422
        """
        return JSONResponse(status_code=422, content=ErrorFormatter.format_validation_error(exc))


    @app.exception_handler(RequestValidationError)
    async def request_validation_exception_handler(_request: Request, exc: RequestValidationError):
        """Handle FastAPI request validation errors (automatic request parsing).

        This handles ValidationErrors that occur during FastAPI's automatic request
        parsing before the request reaches your endpoint.

        Args:
            _request: The FastAPI request object that triggered validation error.
            exc: The RequestValidationError exception containing failure details.

        Returns:
            JSONResponse: A 422 Unprocessable Entity response with error details.
        """
        if _request.url.path.startswith("/tools"):
            error_details = []

            for error in exc.errors():
                loc = error.get("loc", [])
                msg = error.get("msg", "Unknown error")
                ctx = error.get("ctx", {"error": {}})
                type_ = error.get("type", "value_error")
                # Ensure ctx is JSON serializable
                if isinstance(ctx, dict):
                    ctx_serializable = {k: (str(v) if isinstance(v, Exception) else v) for k, v in ctx.items()}
                else:
                    ctx_serializable = str(ctx)
                error_detail = {"type": type_, "loc": loc, "msg": msg, "ctx": ctx_serializable}
                error_details.append(error_detail)

            response_content = {"detail": error_details}
            return JSONResponse(status_code=422, content=response_content)
        return await fastapi_default_validation_handler(_request, exc)


    @app.exception_handler(IntegrityError)
    async def database_exception_handler(_request: Request, exc: IntegrityError):
        """Handle SQLAlchemy database integrity constraint violations globally.

        Intercepts IntegrityError exceptions (e.g., unique constraint violations,
        foreign key constraints) and returns a properly formatted JSON error response.
        This provides consistent error handling for database constraint violations
        across the entire application.

        Args:
            _request: The FastAPI request object that triggered the database error.
                    (Unused but required by FastAPI's exception handler interface)
            exc: The SQLAlchemy IntegrityError exception containing constraint
                violation details.

        Returns:
            JSONResponse: A 409 Conflict response with formatted database error details.

        Examples:
            >>> from sqlalchemy.exc import IntegrityError
            >>> from fastapi import Request
            >>> import asyncio
            >>>
            >>> # Create a mock integrity error
            >>> mock_error = IntegrityError("statement", {}, Exception("duplicate key"))
            >>> result = asyncio.run(database_exception_handler(None, mock_error))
            >>> result.status_code
            409
            >>> # Verify ErrorFormatter.format_database_error is called
            >>> hasattr(result, 'body')
            True
        """
        return JSONResponse(status_code=409, content=ErrorFormatter.format_database_error(exc))
    
    # Legacy deprecation routes
    def could_be_legacy_path(path: str) -> bool:
        """
        Check if the given request path looks like a legacy (unversioned) API path.
        Legacy paths:
        - Don't start with /v1 or /experimental
        - Are not just the root path (/)
        """
        normalized = path.strip().lower()

        # Ignore root and docs
        if normalized in {"/", "/docs", "/openapi.json", "/redoc"}:
            return False

        # If it already starts with /v1 or /experimental, it's not legacy
        if normalized.startswith("/v1") or normalized.startswith("/experimental"):
            return False

        # All other paths could be legacy
        return True

    @app.exception_handler(404)
    async def legacy_path_404_handler(request: Request, exc: HTTPException):
        if could_be_legacy_path(request.url.path):
            return JSONResponse(
                status_code=404,
                content={
                    "error": "API endpoint not found",
                    "message": f"Did you mean /v1{request.url.path}?",
                    "migration_guide": "/docs/migration-urgent",
                    "removed_in": "0.7.0"
                }
            )
        return JSONResponse(status_code=404, content={"error": "Not found"})


    # Set up Jinja2 templates and store in app state for later use
    templates = Jinja2Templates(directory=str(settings.templates_dir))
    app.state.templates = templates


    def require_api_key(api_key: str) -> None:
        """Validates the provided API key.

        This function checks if the provided API key matches the expected one
        based on the settings. If the validation fails, it raises an HTTPException
        with a 401 Unauthorized status.

        Args:
            api_key (str): The API key provided by the user or client.

        Raises:
            HTTPException: If the API key is invalid, a 401 Unauthorized error is raised.

        Examples:
            >>> from mcpgateway.config import settings
            >>> settings.auth_required = True
            >>> settings.basic_auth_user = "admin"
            >>> settings.basic_auth_password = "secret"
            >>>
            >>> # Valid API key
            >>> require_api_key("admin:secret")  # Should not raise
            >>>
            >>> # Invalid API key
            >>> try:
            ...     require_api_key("wrong:key")
            ... except HTTPException as e:
            ...     e.status_code
            401
        """
        if settings.auth_required:
            expected = f"{settings.basic_auth_user}:{settings.basic_auth_password}"
            if api_key != expected:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")



    ####################
    # Healthcheck      #
    ####################
    @app.get("/health")
    async def healthcheck(db: Session = Depends(get_db)):
        """
        Perform a basic health check to verify database connectivity.

        Args:
            db: SQLAlchemy session dependency.

        Returns:
            A dictionary with the health status and optional error message.
        """
        try:
            # Execute the query using text() for an explicit textual SQL expression.
            db.execute(text("SELECT 1"))
        except Exception as e:
            error_message = f"Database connection error: {str(e)}"
            logger.error(error_message)
            return {"status": "unhealthy", "error": error_message}
        return {"status": "healthy"}


    @app.get("/ready")
    async def readiness_check(db: Session = Depends(get_db)):
        """
        Perform a readiness check to verify if the application is ready to receive traffic.

        Args:
            db: SQLAlchemy session dependency.

        Returns:
            JSONResponse with status 200 if ready, 503 if not.
        """
        try:
            # Run the blocking DB check in a thread to avoid blocking the event loop
            await asyncio.to_thread(db.execute, text("SELECT 1"))
            return JSONResponse(content={"status": "ready"}, status_code=200)
        except Exception as e:
            error_message = f"Readiness check failed: {str(e)}"
            logger.error(error_message)
            return JSONResponse(content={"status": "not ready", "error": error_message}, status_code=503)


    # Mount static files
    # app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")

    # Register the version router
    v1_app = FastAPI(title="MCP Gateway API v1", version="1.0.0")
    setup_v1_routes(v1_app)
    app.mount("/v1", v1_app)
    
    # Experimental API (RBAC protected)  
    exp_app = FastAPI(title="MCP Gateway Experimental", version="0.1.0")
    setup_experimental_routes(exp_app)
    app.mount("/experimental", exp_app)

    # Legacy deprecation routes
    setup_legacy_deprecation_routes(app)


    # Feature flags for admin UI and API
    UI_ENABLED = settings.mcpgateway_ui_enabled
    ADMIN_API_ENABLED = settings.mcpgateway_admin_api_enabled
    logger.info(f"Admin UI enabled: {UI_ENABLED}")
    logger.info(f"Admin API enabled: {ADMIN_API_ENABLED}")

    # Conditional UI and admin API handling
    if ADMIN_API_ENABLED:
        logger.info("Including admin_router - Admin API enabled")
        app.include_router(admin_router)  # Admin routes imported from admin.py
    else:
        logger.warning("Admin API routes not mounted - Admin API disabled via MCPGATEWAY_ADMIN_API_ENABLED=False")

    # Streamable http Mount
    app.mount("/mcp", app=streamable_http_session.handle_streamable_http)

    # Conditional static files mounting and root redirect
    if UI_ENABLED:
        # Mount static files for UI
        logger.info("Mounting static files - UI enabled")
        try:
            app.mount(
                "/static",
                StaticFiles(directory=str(settings.static_dir)),
                name="static",
            )
            logger.info("Static assets served from %s", settings.static_dir)
        except RuntimeError as exc:
            logger.warning(
                "Static dir %s not found - Admin UI disabled (%s)",
                settings.static_dir,
                exc,
            )

        # Redirect root path to admin UI
        @app.get("/")
        async def root_redirect(request: Request):
            """
            Redirects the root path ("/") to "/admin".

            Logs a debug message before redirecting.

            Args:
                request (Request): The incoming HTTP request (used only to build the
                    target URL via :pymeth:`starlette.requests.Request.url_for`).

            Returns:
                RedirectResponse: Redirects to /admin.
            """
            logger.debug("Redirecting root path to /admin")
            root_path = request.scope.get("root_path", "")
            return RedirectResponse(f"{root_path}/admin", status_code=303)
            # return RedirectResponse(request.url_for("admin_home"))

    else:
        # If UI is disabled, provide API info at root
        logger.warning("Static files not mounted - UI disabled via MCPGATEWAY_UI_ENABLED=False")

        @app.get("/")
        async def root_info():
            """
            Returns basic API information at the root path.

            Logs an info message indicating UI is disabled and provides details
            about the app, including its name, version, and whether the UI and
            admin API are enabled.

            Returns:
                dict: API info with app name, version, and UI/admin API status.
            """
            logger.info("UI disabled, serving API info at root path")
            return {"name": settings.app_name, "version": __version__, "description": f"{settings.app_name} API - UI is disabled", "ui_enabled": False, "admin_api_enabled": ADMIN_API_ENABLED}


    # Expose some endpoints at the root level as well
    app.post("/initialize")(initialize)
    app.post("/notifications")(handle_notification)

    return app