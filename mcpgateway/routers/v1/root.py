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
    Depends,
)
from fastapi.responses import StreamingResponse

# First-Party
from mcpgateway import __version__
from mcpgateway.admin import admin_router
from mcpgateway.bootstrap_db import main as bootstrap_db
from mcpgateway.cache import ResourceCache, SessionRegistry
from mcpgateway.config import jsonpath_modifier, settings
from mcpgateway.db import refresh_slugs_on_startup, SessionLocal, get_db
from mcpgateway.handlers.sampling import SamplingHandler
from mcpgateway.models import (
    Root,
)
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.root_service import RootService
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


# Import the admin routes from the new module
from mcpgateway.version import router as version_router

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("root routers")

# Initialize services
root_service = RootService()

# Create API router
root_router = APIRouter(prefix="/roots", tags=["Roots"])


@root_router.get("", response_model=List[Root])
@root_router.get("/", response_model=List[Root])
async def list_roots(
    user: str = Depends(require_auth),
) -> List[Root]:
    """
    Retrieve a list of all registered roots.

    Args:
        user: Authenticated user.

    Returns:
        List of Root objects.
    """
    logger.debug(f"User '{user}' requested list of roots")
    return await root_service.list_roots()


@root_router.post("", response_model=Root)
@root_router.post("/", response_model=Root)
async def add_root(
    root: Root,  # Accept JSON body using the Root model from models.py
    user: str = Depends(require_auth),
) -> Root:
    """
    Add a new root.

    Args:
        root: Root object containing URI and name.
        user: Authenticated user.

    Returns:
        The added Root object.
    """
    logger.debug(f"User '{user}' requested to add root: {root}")
    return await root_service.add_root(str(root.uri), root.name)


@root_router.delete("/{uri:path}")
async def remove_root(
    uri: str,
    user: str = Depends(require_auth),
) -> Dict[str, str]:
    """
    Remove a registered root by URI.

    Args:
        uri: URI of the root to remove.
        user: Authenticated user.

    Returns:
        Status message indicating result.
    """
    logger.debug(f"User '{user}' requested to remove root with URI: {uri}")
    await root_service.remove_root(uri)
    return {"status": "success", "message": f"Root {uri} removed"}


@root_router.get("/changes")
async def subscribe_roots_changes(
    user: str = Depends(require_auth),
) -> StreamingResponse:
    """
    Subscribe to real-time changes in root list via Server-Sent Events (SSE).

    Args:
        user: Authenticated user.

    Returns:
        StreamingResponse with event-stream media type.
    """
    logger.debug(f"User '{user}' subscribed to root changes stream")
    return StreamingResponse(root_service.subscribe_changes(), media_type="text/event-stream")
