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
from typing import Any, AsyncIterator, Dict, List, Optional, Union
from urllib.parse import urlparse, urlunparse

# Third-Party
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
)
from fastapi.background import BackgroundTasks
from fastapi.exception_handlers import request_validation_exception_handler as fastapi_default_validation_handler
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


# First-Party
from mcpgateway import __version__
from mcpgateway.admin import admin_router
from mcpgateway.bootstrap_db import main as bootstrap_db
from mcpgateway.cache import ResourceCache, SessionRegistry
from mcpgateway.config import jsonpath_modifier, settings
from mcpgateway.db import refresh_slugs_on_startup, SessionLocal, get_db
from mcpgateway.handlers.sampling import SamplingHandler

from mcpgateway.schemas import (
    PromptRead,
    ResourceRead,
    ServerCreate,
    ServerRead,
    ServerUpdate,
    ToolRead,
)

from mcpgateway.services.logging_service import LoggingService


from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import (
    ServerError,
    ServerNameConflictError,
    ServerNotFoundError,
    ServerService,
)

from mcpgateway.transports.sse_transport import SSETransport
from mcpgateway.transports.streamablehttp_transport import (
    streamable_http_auth,
)
from mcpgateway.utils.db_isready import wait_for_db_ready
from mcpgateway.utils.error_formatter import ErrorFormatter
from mcpgateway.utils.redis_isready import wait_for_redis_ready
from mcpgateway.utils.retry_manager import ResilientHttpClient
from mcpgateway.utils.verify_credentials import require_auth, require_auth_override
from mcpgateway.registry import session_registry


# Import the admin routes from the new module
from mcpgateway.version import router as version_router


# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("server routes")

# Initialize services
server_service = ServerService()

# Create API router
server_router = APIRouter(prefix="/servers", tags=["Servers"])

# APIs
@server_router.get("", response_model=List[ServerRead])
@server_router.get("/", response_model=List[ServerRead])
async def list_servers(
    include_inactive: bool = False,
    tags: Optional[str] = None,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[ServerRead]:
    """
    Lists all servers in the system, optionally including inactive ones.

    Args:
        include_inactive (bool): Whether to include inactive servers in the response.
        tags (Optional[str]): Comma-separated list of tags to filter by.
        db (Session): The database session used to interact with the data store.
        user (str): The authenticated user making the request.

    Returns:
        List[ServerRead]: A list of server objects.
    """
    # Parse tags parameter if provided
    tags_list = None
    if tags:
        tags_list = [tag.strip() for tag in tags.split(",") if tag.strip()]

    logger.debug(f"User {user} requested server list with tags={tags_list}")
    return await server_service.list_servers(db, include_inactive=include_inactive, tags=tags_list)


@server_router.get("/{server_id}", response_model=ServerRead)
async def get_server(server_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> ServerRead:
    """
    Retrieves a server by its ID.

    Args:
        server_id (str): The ID of the server to retrieve.
        db (Session): The database session used to interact with the data store.
        user (str): The authenticated user making the request.

    Returns:
        ServerRead: The server object with the specified ID.

    Raises:
        HTTPException: If the server is not found.
    """
    try:
        logger.debug(f"User {user} requested server with ID {server_id}")
        return await server_service.get_server(db, server_id)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@server_router.post("", response_model=ServerRead, status_code=201)
@server_router.post("/", response_model=ServerRead, status_code=201)
async def create_server(
    server: ServerCreate,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> ServerRead:
    """
    Creates a new server.

    Args:
        server (ServerCreate): The data for the new server.
        db (Session): The database session used to interact with the data store.
        user (str): The authenticated user making the request.

    Returns:
        ServerRead: The created server object.

    Raises:
        HTTPException: If there is a conflict with the server name or other errors.
    """
    try:
        logger.debug(f"User {user} is creating a new server")
        return await server_service.register_server(db, server)
    except ServerNameConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ServerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValidationError as e:
        logger.error(f"Validation error while creating server: {e}")
        raise HTTPException(status_code=422, detail=ErrorFormatter.format_validation_error(e))
    except IntegrityError as e:
        logger.error(f"Integrity error while creating server: {e}")
        raise HTTPException(status_code=409, detail=ErrorFormatter.format_database_error(e))


@server_router.put("/{server_id}", response_model=ServerRead)
async def update_server(
    server_id: str,
    server: ServerUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> ServerRead:
    """
    Updates the information of an existing server.

    Args:
        server_id (str): The ID of the server to update.
        server (ServerUpdate): The updated server data.
        db (Session): The database session used to interact with the data store.
        user (str): The authenticated user making the request.

    Returns:
        ServerRead: The updated server object.

    Raises:
        HTTPException: If the server is not found, there is a name conflict, or other errors.
    """
    try:
        logger.debug(f"User {user} is updating server with ID {server_id}")
        return await server_service.update_server(db, server_id, server)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ServerNameConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ServerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValidationError as e:
        logger.error(f"Validation error while updating server {server_id}: {e}")
        raise HTTPException(status_code=422, detail=ErrorFormatter.format_validation_error(e))
    except IntegrityError as e:
        logger.error(f"Integrity error while updating server {server_id}: {e}")
        raise HTTPException(status_code=409, detail=ErrorFormatter.format_database_error(e))


@server_router.post("/{server_id}/toggle", response_model=ServerRead)
async def toggle_server_status(
    server_id: str,
    activate: bool = True,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> ServerRead:
    """
    Toggles the status of a server (activate or deactivate).

    Args:
        server_id (str): The ID of the server to toggle.
        activate (bool): Whether to activate or deactivate the server.
        db (Session): The database session used to interact with the data store.
        user (str): The authenticated user making the request.

    Returns:
        ServerRead: The server object after the status change.

    Raises:
        HTTPException: If the server is not found or there is an error.
    """
    try:
        logger.debug(f"User {user} is toggling server with ID {server_id} to {'active' if activate else 'inactive'}")
        return await server_service.toggle_server_status(db, server_id, activate)
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ServerError as e:
        raise HTTPException(status_code=400, detail=str(e))


@server_router.delete("/{server_id}", response_model=Dict[str, str])
async def delete_server(server_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, str]:
    """
    Deletes a server by its ID.

    Args:
        server_id (str): The ID of the server to delete.
        db (Session): The database session used to interact with the data store.
        user (str): The authenticated user making the request.

    Returns:
        Dict[str, str]: A success message indicating the server was deleted.

    Raises:
        HTTPException: If the server is not found or there is an error.
    """
    try:
        logger.debug(f"User {user} is deleting server with ID {server_id}")
        await server_service.delete_server(db, server_id)
        return {
            "status": "success",
            "message": f"Server {server_id} deleted successfully",
        }
    except ServerNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ServerError as e:
        raise HTTPException(status_code=400, detail=str(e))


@server_router.get("/{server_id}/sse")
async def sse_endpoint(request: Request, server_id: str, user: str = Depends(require_auth)):
    """
    Establishes a Server-Sent Events (SSE) connection for real-time updates about a server.

    Args:
        request (Request): The incoming request.
        server_id (str): The ID of the server for which updates are received.
        user (str): The authenticated user making the request.

    Returns:
        The SSE response object for the established connection.

    Raises:
        HTTPException: If there is an error in establishing the SSE connection.
    """
    try:
        logger.debug(f"User {user} is establishing SSE connection for server {server_id}")
        base_url = update_url_protocol(request)
        server_sse_url = f"{base_url}/servers/{server_id}"

        transport = SSETransport(base_url=server_sse_url)
        await transport.connect()
        await session_registry.add_session(transport.session_id, transport)
        response = await transport.create_sse_response(request)

        asyncio.create_task(session_registry.respond(server_id, user, session_id=transport.session_id, base_url=base_url))

        tasks = BackgroundTasks()
        tasks.add_task(session_registry.remove_session, transport.session_id)
        response.background = tasks
        logger.info(f"SSE connection established: {transport.session_id}")
        return response
    except Exception as e:
        logger.error(f"SSE connection error: {e}")
        raise HTTPException(status_code=500, detail="SSE connection failed")


@server_router.post("/{server_id}/message")
async def message_endpoint(request: Request, server_id: str, user: str = Depends(require_auth)):
    """
    Handles incoming messages for a specific server.

    Args:
        request (Request): The incoming message request.
        server_id (str): The ID of the server receiving the message.
        user (str): The authenticated user making the request.

    Returns:
        JSONResponse: A success status after processing the message.

    Raises:
        HTTPException: If there are errors processing the message.
    """
    try:
        logger.debug(f"User {user} sent a message to server {server_id}")
        session_id = request.query_params.get("session_id")
        if not session_id:
            logger.error("Missing session_id in message request")
            raise HTTPException(status_code=400, detail="Missing session_id")

        message = await request.json()

        await session_registry.broadcast(
            session_id=session_id,
            message=message,
        )

        return JSONResponse(content={"status": "success"}, status_code=202)
    except ValueError as e:
        logger.error(f"Invalid message format: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Message handling error: {e}")
        raise HTTPException(status_code=500, detail="Failed to process message")


@server_router.get("/{server_id}/tools", response_model=List[ToolRead])
async def server_get_tools(
    server_id: str,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[ToolRead]:
    """
    List tools for the server  with an option to include inactive tools.

    This endpoint retrieves a list of tools from the database, optionally including
    those that are inactive. The inactive filter helps administrators manage tools
    that have been deactivated but not deleted from the system.

    Args:
        server_id (str): ID of the server
        include_inactive (bool): Whether to include inactive tools in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        List[ToolRead]: A list of tool records formatted with by_alias=True.
    """
    logger.debug(f"User: {user} has listed tools for the server_id: {server_id}")
    tools = await tool_service.list_server_tools(db, server_id=server_id, include_inactive=include_inactive)
    return [tool.model_dump(by_alias=True) for tool in tools]


@server_router.get("/{server_id}/resources", response_model=List[ResourceRead])
async def server_get_resources(
    server_id: str,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[ResourceRead]:
    """
    List resources for the server with an option to include inactive resources.

    This endpoint retrieves a list of resources from the database, optionally including
    those that are inactive. The inactive filter is useful for administrators who need
    to view or manage resources that have been deactivated but not deleted.

    Args:
        server_id (str): ID of the server
        include_inactive (bool): Whether to include inactive resources in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        List[ResourceRead]: A list of resource records formatted with by_alias=True.
    """
    logger.debug(f"User: {user} has listed resources for the server_id: {server_id}")
    resources = await resource_service.list_server_resources(db, server_id=server_id, include_inactive=include_inactive)
    return [resource.model_dump(by_alias=True) for resource in resources]


@server_router.get("/{server_id}/prompts", response_model=List[PromptRead])
async def server_get_prompts(
    server_id: str,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> List[PromptRead]:
    """
    List prompts for the server with an option to include inactive prompts.

    This endpoint retrieves a list of prompts from the database, optionally including
    those that are inactive. The inactive filter helps administrators see and manage
    prompts that have been deactivated but not deleted from the system.

    Args:
        server_id (str): ID of the server
        include_inactive (bool): Whether to include inactive prompts in the results.
        db (Session): Database session dependency.
        user (str): Authenticated user dependency.

    Returns:
        List[PromptRead]: A list of prompt records formatted with by_alias=True.
    """
    logger.debug(f"User: {user} has listed prompts for the server_id: {server_id}")
    prompts = await prompt_service.list_server_prompts(db, server_id=server_id, include_inactive=include_inactive)
    return [prompt.model_dump(by_alias=True) for prompt in prompts]