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
logger = logging_service.get_logger("tag routes")


# Initialize service
tag_service = TagService()

# Create API router
tag_router = APIRouter(prefix="/tags", tags=["Tags"])

# APIs
@tag_router.get("", response_model=List[TagInfo])
@tag_router.get("/", response_model=List[TagInfo])
async def list_tags(
    entity_types: Optional[str] = None,
    include_entities: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[TagInfo]:
    """
    Retrieve all unique tags across specified entity types.

    Args:
        entity_types: Comma-separated list of entity types to filter by
                     (e.g., "tools,resources,prompts,servers,gateways").
                     If not provided, returns tags from all entity types.
        include_entities: Whether to include the list of entities that have each tag
        db: Database session
        user: Authenticated user

    Returns:
        List of TagInfo objects containing tag names, statistics, and optionally entities

    Raises:
        HTTPException: If tag retrieval fails
    """
    # Parse entity types parameter if provided
    entity_types_list = None
    if entity_types:
        entity_types_list = [et.strip().lower() for et in entity_types.split(",") if et.strip()]

    logger.debug(f"User {user} is retrieving tags for entity types: {entity_types_list}, include_entities: {include_entities}")

    try:
        tags = await tag_service.get_all_tags(db, entity_types=entity_types_list, include_entities=include_entities)
        return tags
    except Exception as e:
        logger.error(f"Failed to retrieve tags: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve tags: {str(e)}")


@tag_router.get("/{tag_name}/entities", response_model=List[TaggedEntity])
async def get_entities_by_tag(
    tag_name: str,
    entity_types: Optional[str] = None,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[TaggedEntity]:
    """
    Get all entities that have a specific tag.

    Args:
        tag_name: The tag to search for
        entity_types: Comma-separated list of entity types to filter by
                     (e.g., "tools,resources,prompts,servers,gateways").
                     If not provided, returns entities from all types.
        db: Database session
        user: Authenticated user

    Returns:
        List of TaggedEntity objects

    Raises:
        HTTPException: If entity retrieval fails
    """
    # Parse entity types parameter if provided
    entity_types_list = None
    if entity_types:
        entity_types_list = [et.strip().lower() for et in entity_types.split(",") if et.strip()]

    logger.debug(f"User {user} is retrieving entities for tag '{tag_name}' with entity types: {entity_types_list}")

    try:
        entities = await tag_service.get_entities_by_tag(db, tag_name=tag_name, entity_types=entity_types_list)
        return entities
    except Exception as e:
        logger.error(f"Failed to retrieve entities for tag '{tag_name}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve entities: {str(e)}")
