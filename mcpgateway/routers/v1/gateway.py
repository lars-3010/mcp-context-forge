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
    APIRouter,
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    status,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.background import BackgroundTasks
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
from mcpgateway.models import (
    InitializeRequest,
    InitializeResult,
    ListResourceTemplatesResult,
    LogLevel,
    ResourceContent,
    Root,
)
from mcpgateway.plugins import PluginManager, PluginViolationError
from mcpgateway.schemas import (
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
from mcpgateway.services.completion_service import CompletionService
from mcpgateway.services.gateway_service import GatewayConnectionError, GatewayNameConflictError, GatewayService
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.prompt_service import (
    PromptError,
    PromptNameConflictError,
    PromptNotFoundError,
    PromptService,
)
from mcpgateway.services.resource_service import (
    ResourceError,
    ResourceNotFoundError,
    ResourceService,
    ResourceURIConflictError,
)
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import (
    ServerError,
    ServerNameConflictError,
    ServerNotFoundError,
    ServerService,
)
from mcpgateway.services.tag_service import TagService
from mcpgateway.services.tool_service import (
    ToolError,
    ToolNameConflictError,
    ToolService,
)
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
from mcpgateway.validation.jsonrpc import (
    JSONRPCError,
)

# Import the admin routes from the new module
from mcpgateway.version import router as version_router

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("gateway routes")


# Initialize services
gateway_service = GatewayService()

# Create API router
gateway_router = APIRouter(prefix="/gateways", tags=["Gateways"])

@gateway_router.post("/{gateway_id}/toggle")
async def toggle_gateway_status(
    gateway_id: str,
    activate: bool = True,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Toggle the activation status of a gateway.

    Args:
        gateway_id (str): String ID of the gateway to toggle.
        activate (bool): ``True`` to activate, ``False`` to deactivate.
        db (Session): Active SQLAlchemy session.
        user (str): Authenticated username.

    Returns:
        Dict[str, Any]: A dict containing the operation status, a message, and the updated gateway object.

    Raises:
        HTTPException: Returned with **400 Bad Request** if the toggle operation fails (e.g., the gateway does not exist or the database raises an unexpected error).
    """
    logger.debug(f"User '{user}' requested toggle for gateway {gateway_id}, activate={activate}")
    try:
        gateway = await gateway_service.toggle_gateway_status(
            db,
            gateway_id,
            activate,
        )
        return {
            "status": "success",
            "message": f"Gateway {gateway_id} {'activated' if activate else 'deactivated'}",
            "gateway": gateway.model_dump(),
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@gateway_router.get("", response_model=List[GatewayRead])
@gateway_router.get("/", response_model=List[GatewayRead])
async def list_gateways(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[GatewayRead]:
    """
    List all gateways.

    Args:
        include_inactive: Include inactive gateways.
        db: Database session.
        user: Authenticated user.

    Returns:
        List of gateway records.
    """
    logger.debug(f"User '{user}' requested list of gateways with include_inactive={include_inactive}")
    return await gateway_service.list_gateways(db, include_inactive=include_inactive)


@gateway_router.post("", response_model=GatewayRead)
@gateway_router.post("/", response_model=GatewayRead)
async def register_gateway(
    gateway: GatewayCreate,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> GatewayRead:
    """
    Register a new gateway.

    Args:
        gateway: Gateway creation data.
        db: Database session.
        user: Authenticated user.

    Returns:
        Created gateway.
    """
    logger.debug(f"User '{user}' requested to register gateway: {gateway}")
    try:
        return await gateway_service.register_gateway(db, gateway)
    except Exception as ex:
        if isinstance(ex, GatewayConnectionError):
            return JSONResponse(content={"message": "Unable to connect to gateway"}, status_code=502)
        if isinstance(ex, ValueError):
            return JSONResponse(content={"message": "Unable to process input"}, status_code=400)
        if isinstance(ex, GatewayNameConflictError):
            return JSONResponse(content={"message": "Gateway name already exists"}, status_code=400)
        if isinstance(ex, RuntimeError):
            return JSONResponse(content={"message": "Error during execution"}, status_code=500)
        if isinstance(ex, ValidationError):
            return JSONResponse(content=ErrorFormatter.format_validation_error(ex), status_code=422)
        if isinstance(ex, IntegrityError):
            return JSONResponse(status_code=409, content=ErrorFormatter.format_database_error(ex))
        return JSONResponse(content={"message": "Unexpected error"}, status_code=500)


@gateway_router.get("/{gateway_id}", response_model=GatewayRead)
async def get_gateway(gateway_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> GatewayRead:
    """
    Retrieve a gateway by ID.

    Args:
        gateway_id: ID of the gateway.
        db: Database session.
        user: Authenticated user.

    Returns:
        Gateway data.
    """
    logger.debug(f"User '{user}' requested gateway {gateway_id}")
    return await gateway_service.get_gateway(db, gateway_id)


@gateway_router.put("/{gateway_id}", response_model=GatewayRead)
async def update_gateway(
    gateway_id: str,
    gateway: GatewayUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> GatewayRead:
    """
    Update a gateway.

    Args:
        gateway_id: Gateway ID.
        gateway: Gateway update data.
        db: Database session.
        user: Authenticated user.

    Returns:
        Updated gateway.
    """
    logger.debug(f"User '{user}' requested update on gateway {gateway_id} with data={gateway}")
    return await gateway_service.update_gateway(db, gateway_id, gateway)


@gateway_router.delete("/{gateway_id}")
async def delete_gateway(gateway_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, str]:
    """
    Delete a gateway by ID.

    Args:
        gateway_id: ID of the gateway.
        db: Database session.
        user: Authenticated user.

    Returns:
        Status message.
    """
    logger.debug(f"User '{user}' requested deletion of gateway {gateway_id}")
    await gateway_service.delete_gateway(db, gateway_id)
    return {"status": "success", "message": f"Gateway {gateway_id} deleted"}
