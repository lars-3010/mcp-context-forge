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
import logging
from typing import Any, Dict, List, Optional

# Third-Party
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# First-Party
from mcpgateway import __version__
from mcpgateway.admin import admin_router
from mcpgateway.bootstrap_db import main as bootstrap_db
from mcpgateway.cache import ResourceCache, SessionRegistry
from mcpgateway.config import settings
from mcpgateway.db import SessionLocal, get_db
from mcpgateway.handlers.sampling import SamplingHandler
from mcpgateway.models import (
    ListResourceTemplatesResult,
    ResourceContent,
)
from mcpgateway.schemas import (
    ResourceCreate,
    ResourceRead,
    ResourceUpdate,
)
from mcpgateway.services.logging_service import LoggingService

from mcpgateway.services.resource_service import (
    ResourceError,
    ResourceNotFoundError,
    ResourceService,
    ResourceURIConflictError,
)
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.verify_credentials import require_auth


# Import the admin routes from the new module
from mcpgateway.version import router as version_router

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("resource routes")

# Initialize services
resource_service = ResourceService()

# Initialize cache
resource_cache = ResourceCache(max_size=settings.resource_cache_size, ttl=settings.resource_cache_ttl)

# Create API router
resource_router = APIRouter(prefix="/resources", tags=["Resources"])

async def invalidate_resource_cache(uri: Optional[str] = None) -> None:
    """
    Invalidates the resource cache.

    If a specific URI is provided, only that resource will be removed from the cache.
    If no URI is provided, the entire resource cache will be cleared.

    Args:
        uri (Optional[str]): The URI of the resource to invalidate from the cache. If None, the entire cache is cleared.

    Examples:
        >>> import asyncio
        >>> # Test clearing specific URI from cache
        >>> resource_cache.set("/test/resource", {"content": "test data"})
        >>> resource_cache.get("/test/resource") is not None
        True
        >>> asyncio.run(invalidate_resource_cache("/test/resource"))
        >>> resource_cache.get("/test/resource") is None
        True
        >>>
        >>> # Test clearing entire cache
        >>> resource_cache.set("/resource1", {"content": "data1"})
        >>> resource_cache.set("/resource2", {"content": "data2"})
        >>> asyncio.run(invalidate_resource_cache())
        >>> resource_cache.get("/resource1") is None and resource_cache.get("/resource2") is None
        True
    """
    if uri:
        resource_cache.delete(uri)
    else:
        resource_cache.clear()


# --- Resource templates endpoint - MUST come before variable paths ---
@resource_router.get("/templates/list", response_model=ListResourceTemplatesResult)
async def list_resource_templates(
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> ListResourceTemplatesResult:
    """
    List all available resource templates.

    Args:
        db (Session): Database session.
        user (str): Authenticated user.

    Returns:
        ListResourceTemplatesResult: A paginated list of resource templates.
    """
    logger.debug(f"User {user} requested resource templates")
    resource_templates = await resource_service.list_resource_templates(db)
    # For simplicity, we're not implementing real pagination here
    return ListResourceTemplatesResult(_meta={}, resource_templates=resource_templates, next_cursor=None)  # No pagination for now


@resource_router.post("/{resource_id}/toggle")
async def toggle_resource_status(
    resource_id: int,
    activate: bool = True,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Activate or deactivate a resource by its ID.

    Args:
        resource_id (int): The ID of the resource.
        activate (bool): True to activate, False to deactivate.
        db (Session): Database session.
        user (str): Authenticated user.

    Returns:
        Dict[str, Any]: Status message and updated resource data.

    Raises:
        HTTPException: If toggling fails.
    """
    logger.debug(f"User {user} is toggling resource with ID {resource_id} to {'active' if activate else 'inactive'}")
    try:
        resource = await resource_service.toggle_resource_status(db, resource_id, activate)
        return {
            "status": "success",
            "message": f"Resource {resource_id} {'activated' if activate else 'deactivated'}",
            "resource": resource.model_dump(),
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@resource_router.get("", response_model=List[ResourceRead])
@resource_router.get("/", response_model=List[ResourceRead])
async def list_resources(
    cursor: Optional[str] = None,
    include_inactive: bool = False,
    tags: Optional[str] = None,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[ResourceRead]:
    """
    Retrieve a list of resources.

    Args:
        cursor (Optional[str]): Optional cursor for pagination.
        include_inactive (bool): Whether to include inactive resources.
        tags (Optional[str]): Comma-separated list of tags to filter by.
        db (Session): Database session.
        user (str): Authenticated user.

    Returns:
        List[ResourceRead]: List of resources.
    """
    # Parse tags parameter if provided
    tags_list = None
    if tags:
        tags_list = [tag.strip() for tag in tags.split(",") if tag.strip()]

    logger.debug(f"User {user} requested resource list with cursor {cursor}, include_inactive={include_inactive}, tags={tags_list}")
    if cached := resource_cache.get("resource_list"):
        return cached
    # Pass the cursor parameter
    resources = await resource_service.list_resources(db, include_inactive=include_inactive, tags=tags_list)
    resource_cache.set("resource_list", resources)
    return resources


@resource_router.post("", response_model=ResourceRead)
@resource_router.post("/", response_model=ResourceRead)
async def create_resource(
    resource: ResourceCreate,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> ResourceRead:
    """
    Create a new resource.

    Args:
        resource (ResourceCreate): Data for the new resource.
        db (Session): Database session.
        user (str): Authenticated user.

    Returns:
        ResourceRead: The created resource.

    Raises:
        HTTPException: On conflict or validation errors or IntegrityError.
    """
    logger.debug(f"User {user} is creating a new resource")
    try:
        result = await resource_service.register_resource(db, resource)
        return result
    except ResourceURIConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ResourceError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValidationError as e:
        # Handle validation errors from Pydantic
        logger.error(f"Validation error while creating resource: {e}")
        raise HTTPException(status_code=422, detail=ErrorFormatter.format_validation_error(e))
    except IntegrityError as e:
        logger.error(f"Integrity error while creating resource: {e}")
        raise HTTPException(status_code=409, detail=ErrorFormatter.format_database_error(e))


@resource_router.get("/{uri:path}")
async def read_resource(uri: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> ResourceContent:
    """
    Read a resource by its URI.

    Args:
        uri (str): URI of the resource.
        db (Session): Database session.
        user (str): Authenticated user.

    Returns:
        ResourceContent: The content of the resource.

    Raises:
        HTTPException: If the resource cannot be found or read.
    """
    logger.debug(f"User {user} requested resource with URI {uri}")
    if cached := resource_cache.get(uri):
        return cached
    try:
        content: ResourceContent = await resource_service.read_resource(db, uri)
    except (ResourceNotFoundError, ResourceError) as exc:
        # Translate to FastAPI HTTP error
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    resource_cache.set(uri, content)
    return content


@resource_router.put("/{uri:path}", response_model=ResourceRead)
async def update_resource(
    uri: str,
    resource: ResourceUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> ResourceRead:
    """
    Update a resource identified by its URI.

    Args:
        uri (str): URI of the resource.
        resource (ResourceUpdate): New resource data.
        db (Session): Database session.
        user (str): Authenticated user.

    Returns:
        ResourceRead: The updated resource.

    Raises:
        HTTPException: If the resource is not found or update fails.
    """
    try:
        logger.debug(f"User {user} is updating resource with URI {uri}")
        result = await resource_service.update_resource(db, uri, resource)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValidationError as e:
        logger.error(f"Validation error while updating resource {uri}: {e}")
        raise HTTPException(status_code=422, detail=ErrorFormatter.format_validation_error(e))
    except IntegrityError as e:
        logger.error(f"Integrity error while updating resource {uri}: {e}")
        raise HTTPException(status_code=409, detail=ErrorFormatter.format_database_error(e))
    await invalidate_resource_cache(uri)
    return result


@resource_router.delete("/{uri:path}")
async def delete_resource(uri: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, str]:
    """
    Delete a resource by its URI.

    Args:
        uri (str): URI of the resource to delete.
        db (Session): Database session.
        user (str): Authenticated user.

    Returns:
        Dict[str, str]: Status message indicating deletion success.

    Raises:
        HTTPException: If the resource is not found or deletion fails.
    """
    try:
        logger.debug(f"User {user} is deleting resource with URI {uri}")
        await resource_service.delete_resource(db, uri)
        await invalidate_resource_cache(uri)
        return {"status": "success", "message": f"Resource {uri} deleted"}
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ResourceError as e:
        raise HTTPException(status_code=400, detail=str(e))


@resource_router.post("/subscribe/{uri:path}")
async def subscribe_resource(uri: str, user: str = Depends(require_auth)) -> StreamingResponse:
    """
    Subscribe to server-sent events (SSE) for a specific resource.

    Args:
        uri (str): URI of the resource to subscribe to.
        user (str): Authenticated user.

    Returns:
        StreamingResponse: A streaming response with event updates.
    """
    logger.debug(f"User {user} is subscribing to resource with URI {uri}")
    return StreamingResponse(resource_service.subscribe_events(uri), media_type="text/event-stream")
