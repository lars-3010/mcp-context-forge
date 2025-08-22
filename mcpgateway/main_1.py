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
import time
from typing import Any, AsyncIterator, Dict, List, Optional, Union
from urllib.parse import urlparse, urlunparse
import uuid

# Third-Party
from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Request, status, WebSocket, WebSocketDisconnect
from fastapi.background import BackgroundTasks
from fastapi.exception_handlers import request_validation_exception_handler as fastapi_default_validation_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

# First-Party
from mcpgateway import __version__
from mcpgateway.admin import admin_router, set_logging_service
from mcpgateway.bootstrap_db import main as bootstrap_db
from mcpgateway.cache import ResourceCache, SessionRegistry
from mcpgateway.config import settings
from mcpgateway.db import Prompt as DbPrompt
from mcpgateway.db import refresh_slugs_on_startup, SessionLocal
from mcpgateway.db import Tool as DbTool
from mcpgateway.handlers.sampling import SamplingHandler
from mcpgateway.middleware.security_headers import SecurityHeadersMiddleware
from mcpgateway.models import InitializeResult, ListResourceTemplatesResult, LogLevel, ResourceContent, Root
from mcpgateway.observability import init_telemetry
from mcpgateway.plugins.framework import PluginManager, PluginViolationError
from mcpgateway.routers.well_known import router as well_known_router
from mcpgateway.schemas import (
    A2AAgentCreate,
    A2AAgentRead,
    A2AAgentUpdate,
    GatewayCreate,
    GatewayRead,
    GatewayUpdate,
    JsonPathModifier,
    PromptCreate,
    PromptExecuteArgs,
    PromptRead,
    PromptUpdate,
    ResourceCreate,
    ResourceRead,
    ResourceUpdate,
    RPCRequest,
    ServerCreate,
    ServerRead,
    ServerUpdate,
    TaggedEntity,
    TagInfo,
    ToolCreate,
    ToolRead,
    ToolUpdate,
)
from mcpgateway.services.a2a_service import A2AAgentError, A2AAgentNameConflictError, A2AAgentNotFoundError, A2AAgentService
from mcpgateway.services.completion_service import CompletionService
from mcpgateway.services.export_service import ExportError, ExportService
from mcpgateway.services.gateway_service import GatewayConnectionError, GatewayNameConflictError, GatewayNotFoundError, GatewayService
from mcpgateway.services.import_service import ConflictStrategy, ImportConflictError
from mcpgateway.services.import_service import ImportError as ImportServiceError
from mcpgateway.services.import_service import ImportService, ImportValidationError
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.prompt_service import PromptError, PromptNameConflictError, PromptNotFoundError, PromptService
from mcpgateway.services.resource_service import ResourceError, ResourceNotFoundError, ResourceService, ResourceURIConflictError
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import ServerError, ServerNameConflictError, ServerNotFoundError, ServerService
from mcpgateway.services.tag_service import TagService
from mcpgateway.services.tool_service import ToolError, ToolNameConflictError, ToolNotFoundError, ToolService
from mcpgateway.transports.sse_transport import SSETransport
from mcpgateway.transports.streamablehttp_transport import SessionManagerWrapper, streamable_http_auth
from mcpgateway.utils.db_isready import wait_for_db_ready
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.metadata_capture import MetadataCapture
from mcpgateway.utils.passthrough_headers import set_global_passthrough_headers
from mcpgateway.utils.redis_isready import wait_for_redis_ready
from mcpgateway.utils.retry_manager import ResilientHttpClient
from mcpgateway.utils.verify_credentials import require_auth, require_auth_override, verify_jwt_token
from mcpgateway.validation.jsonrpc import JSONRPCError

# Import the admin routes from the new module
from mcpgateway.version import router as version_router

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("mcpgateway")

# Share the logging service with admin module
set_logging_service(logging_service)

# Note: Logging configuration is handled by LoggingService during startup
# Don't use basicConfig here as it conflicts with our dual logging setup

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
export_service = ExportService()
import_service = ImportService()
# Initialize A2A service only if A2A features are enabled
a2a_service = A2AAgentService() if settings.mcpgateway_a2a_enabled else None

# Initialize session manager for Streamable HTTP transport
streamable_http_session = SessionManagerWrapper()

# Wait for redis to be ready
if settings.cache_type == "redis":
    wait_for_redis_ready(redis_url=settings.redis_url, max_retries=int(settings.redis_max_retries), retry_interval_ms=int(settings.redis_retry_interval_ms), sync=True)

# Initialize session registry
session_registry = SessionRegistry(
    backend=settings.cache_type,
    redis_url=settings.redis_url if settings.cache_type == "redis" else None,
    database_url=settings.database_url if settings.cache_type == "database" else None,
    session_ttl=settings.session_ttl,
    message_ttl=settings.message_ttl,
)

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
    # Initialize logging service FIRST to ensure all logging goes to dual output
    await logging_service.initialize()
    logger.info("Starting MCP Gateway services")

    # Initialize observability (Phoenix tracing)
    init_telemetry()
    logger.info("Observability initialized")

    try:
        if plugin_manager:
            await plugin_manager.initialize()
            logger.info(f"Plugin manager initialized with {plugin_manager.plugin_count} plugins")

        if settings.enable_header_passthrough:
            db_gen = get_db()
            db = next(db_gen)  # pylint: disable=stop-iteration-return
            try:
                await set_global_passthrough_headers(db)
            finally:
                db.close()

        await tool_service.initialize()
        await resource_service.initialize()
        await prompt_service.initialize()
        await gateway_service.initialize()
        await root_service.initialize()
        await completion_service.initialize()
        await sampling_handler.initialize()
        await export_service.initialize()
        await import_service.initialize()
        if a2a_service:
            await a2a_service.initialize()
        await resource_cache.initialize()
        await streamable_http_session.initialize()
        refresh_slugs_on_startup()

        logger.info("All services initialized successfully")

        # Reconfigure uvicorn loggers after startup to capture access logs in dual output
        logging_service.configure_uvicorn_after_startup()

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
        # Build service list conditionally
        services_to_shutdown = [
            resource_cache,
            sampling_handler,
            import_service,
            export_service,
            logging_service,
            completion_service,
            root_service,
            gateway_service,
            prompt_service,
            resource_service,
            tool_service,
            streamable_http_session,
        ]

        if a2a_service:
            services_to_shutdown.insert(4, a2a_service)  # Insert after export_service

        for service in services_to_shutdown:
            try:
                await service.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down {service.__class__.__name__}: {str(e)}")
        logger.info("Shutdown complete")


# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="A FastAPI-based MCP Gateway with federation support",
    root_path=settings.app_root_path,
    lifespan=lifespan,
)







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
