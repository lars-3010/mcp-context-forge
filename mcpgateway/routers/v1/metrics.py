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
logger = logging_service.get_logger("mcpgateway")


# Initialize services
tool_service = ToolService()
resource_service = ResourceService()
server_service = ServerService()
prompt_service = PromptService()

# Create API router
metrics_router = APIRouter(prefix="/metrics", tags=["Metrics"])


@metrics_router.get("", response_model=dict)
async def get_metrics(db: Session = Depends(get_db), user: str = Depends(require_auth)) -> dict:
    """
    Retrieve aggregated metrics for all entity types (Tools, Resources, Servers, Prompts).

    Args:
        db: Database session
        user: Authenticated user

    Returns:
        A dictionary with keys for each entity type and their aggregated metrics.
    """
    logger.debug(f"User {user} requested aggregated metrics")
    tool_metrics = await tool_service.aggregate_metrics(db)
    resource_metrics = await resource_service.aggregate_metrics(db)
    server_metrics = await server_service.aggregate_metrics(db)
    prompt_metrics = await prompt_service.aggregate_metrics(db)
    return {
        "tools": tool_metrics,
        "resources": resource_metrics,
        "servers": server_metrics,
        "prompts": prompt_metrics,
    }


@metrics_router.post("/reset", response_model=dict)
async def reset_metrics(entity: Optional[str] = None, entity_id: Optional[int] = None, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> dict:
    """
    Reset metrics for a specific entity type and optionally a specific entity ID,
    or perform a global reset if no entity is specified.

    Args:
        entity: One of "tool", "resource", "server", "prompt", or None for global reset.
        entity_id: Specific entity ID to reset metrics for (optional).
        db: Database session
        user: Authenticated user

    Returns:
        A success message in a dictionary.

    Raises:
        HTTPException: If an invalid entity type is specified.
    """
    logger.debug(f"User {user} requested metrics reset for entity: {entity}, id: {entity_id}")
    if entity is None:
        # Global reset
        await tool_service.reset_metrics(db)
        await resource_service.reset_metrics(db)
        await server_service.reset_metrics(db)
        await prompt_service.reset_metrics(db)
    elif entity.lower() == "tool":
        await tool_service.reset_metrics(db, entity_id)
    elif entity.lower() == "resource":
        await resource_service.reset_metrics(db)
    elif entity.lower() == "server":
        await server_service.reset_metrics(db)
    elif entity.lower() == "prompt":
        await prompt_service.reset_metrics(db)
    else:
        raise HTTPException(status_code=400, detail="Invalid entity type for metrics reset")
    return {"status": "success", "message": f"Metrics reset for {entity if entity else 'all entities'}"}