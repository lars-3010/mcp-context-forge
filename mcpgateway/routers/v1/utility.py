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
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

# First-Party
from mcpgateway import __version__
from mcpgateway.bootstrap_db import main as bootstrap_db
from mcpgateway.config import  settings
from mcpgateway.db import SessionLocal, get_db
from mcpgateway.handlers.sampling import SamplingHandler
from mcpgateway.models import (
    InitializeRequest,
    LogLevel,

)
from mcpgateway.schemas import RPCRequest
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
from mcpgateway.validation.jsonrpc import (
    JSONRPCError,
)
from mcpgateway.registry import session_registry
from mcpgateway.routers.v1.protocol import initialize

# Import the admin routes from the new module
from mcpgateway.version import router as version_router

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("utility routes")

def get_protocol_from_request(request: Request) -> str:
    """
    Return "https" or "http" based on:
     1) X-Forwarded-Proto (if set by a proxy)
     2) request.url.scheme  (e.g. when Gunicorn/Uvicorn is terminating TLS)

    Args:
        request (Request): The FastAPI request object.

    Returns:
        str: The protocol used for the request, either "http" or "https".
    """
    forwarded = request.headers.get("x-forwarded-proto")
    if forwarded:
        # may be a comma-separated list; take the first
        return forwarded.split(",")[0].strip()
    return request.url.scheme

def update_url_protocol(request: Request) -> str:
    """
    Update the base URL protocol based on the request's scheme or forwarded headers.

    Args:
        request (Request): The FastAPI request object.

    Returns:
        str: The base URL with the correct protocol.
    """
    parsed = urlparse(str(request.base_url))
    proto = get_protocol_from_request(request)
    new_parsed = parsed._replace(scheme=proto)
    # urlunparse keeps netloc and path intact
    return urlunparse(new_parsed).rstrip("/")



# Initialize service
tool_service = ToolService()
resource_service = ResourceService()
prompt_service = PromptService()
gateway_service = GatewayService()
root_service = RootService()
completion_service = CompletionService()
sampling_handler = SamplingHandler()
server_service = ServerService()
tag_service = TagService()

# Create API router
utility_router = APIRouter(tags=["Utilities"])

@utility_router.post("/rpc/")
@utility_router.post("/rpc")
async def handle_rpc(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)):  # revert this back
    """Handle RPC requests.

    Args:
        request (Request): The incoming FastAPI request.
        db (Session): Database session.
        user (str): The authenticated user.

    Returns:
        Response with the RPC result or error.
    """
    try:
        logger.debug(f"User {user} made an RPC request")
        body = await request.json()
        method = body["method"]
        # rpc_id = body.get("id")
        params = body.get("params", {})
        cursor = params.get("cursor")  # Extract cursor parameter

        RPCRequest(jsonrpc="2.0", method=method, params=params)  # Validate the request body against the RPCRequest model

        if method == "tools/list":
            tools = await tool_service.list_tools(db, cursor=cursor)
            result = [t.model_dump(by_alias=True, exclude_none=True) for t in tools]
        elif method == "list_tools":  # Legacy endpoint
            tools = await tool_service.list_tools(db, cursor=cursor)
            result = [t.model_dump(by_alias=True, exclude_none=True) for t in tools]
        elif method == "initialize":
            result = initialize(
                InitializeRequest(
                    protocol_version=params.get("protocolVersion") or params.get("protocol_version", ""),
                    capabilities=params.get("capabilities", {}),
                    client_info=params.get("clientInfo") or params.get("client_info", {}),
                ),
                user,
            ).model_dump(by_alias=True, exclude_none=True)
        elif method == "list_gateways":
            gateways = await gateway_service.list_gateways(db, include_inactive=False)
            result = [g.model_dump(by_alias=True, exclude_none=True) for g in gateways]
        elif method == "list_roots":
            roots = await root_service.list_roots()
            result = [r.model_dump(by_alias=True, exclude_none=True) for r in roots]
        elif method == "resources/list":
            resources = await resource_service.list_resources(db)
            result = [r.model_dump(by_alias=True, exclude_none=True) for r in resources]
        elif method == "prompts/list":
            prompts = await prompt_service.list_prompts(db, cursor=cursor)
            result = [p.model_dump(by_alias=True, exclude_none=True) for p in prompts]
        elif method == "prompts/get":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not name:
                raise JSONRPCError(-32602, "Missing prompt name in parameters", params)
            result = await prompt_service.get_prompt(db, name, arguments)
            if hasattr(result, "model_dump"):
                result = result.model_dump(by_alias=True, exclude_none=True)
        elif method == "ping":
            # Per the MCP spec, a ping returns an empty result.
            result = {}
        else:
            try:
                result = await tool_service.invoke_tool(db=db, name=method, arguments=params)
                if hasattr(result, "model_dump"):
                    result = result.model_dump(by_alias=True, exclude_none=True)
            except ValueError:
                result = await gateway_service.forward_request(db, method, params)
                if hasattr(result, "model_dump"):
                    result = result.model_dump(by_alias=True, exclude_none=True)

        response = result
        return response

    except JSONRPCError as e:
        return e.to_dict()
    except Exception as e:
        if isinstance(e, ValueError):
            return JSONResponse(content={"message": "Method invalid"}, status_code=422)
        logger.error(f"RPC error: {str(e)}")
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "Internal error", "data": str(e)},
            "id": body.get("id") if "body" in locals() else None,
        }


@utility_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Handle WebSocket connection to relay JSON-RPC requests to the internal RPC endpoint.

    Accepts incoming text messages, parses them as JSON-RPC requests, sends them to /rpc,
    and returns the result to the client over the same WebSocket.

    Args:
        websocket: The WebSocket connection instance.
    """
    try:
        await websocket.accept()
        while True:
            try:
                data = await websocket.receive_text()
                client_args = {"timeout": settings.federation_timeout, "verify": not settings.skip_ssl_verify}
                async with ResilientHttpClient(client_args=client_args) as client:
                    response = await client.post(
                        f"http://localhost:{settings.port}/rpc",
                        json=json.loads(data),
                        headers={"Content-Type": "application/json"},
                    )
                    await websocket.send_text(response.text)
            except JSONRPCError as e:
                await websocket.send_text(json.dumps(e.to_dict()))
            except json.JSONDecodeError:
                await websocket.send_text(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "error": {"code": -32700, "message": "Parse error"},
                            "id": None,
                        }
                    )
                )
            except Exception as e:
                logger.error(f"WebSocket error: {str(e)}")
                await websocket.close(code=1011)
                break
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket connection error: {str(e)}")
        try:
            await websocket.close(code=1011)
        except Exception as er:
            logger.error(f"Error while closing WebSocket: {er}")


@utility_router.get("/sse")
async def utility_sse_endpoint(request: Request, user: str = Depends(require_auth)):
    """
    Establish a Server-Sent Events (SSE) connection for real-time updates.

    Args:
        request (Request): The incoming HTTP request.
        user (str): Authenticated username.

    Returns:
        StreamingResponse: A streaming response that keeps the connection
        open and pushes events to the client.

    Raises:
        HTTPException: Returned with **500 Internal Server Error** if the SSE connection cannot be established or an unexpected error occurs while creating the transport.
    """
    try:
        logger.debug("User %s requested SSE connection", user)
        base_url = update_url_protocol(request)

        transport = SSETransport(base_url=base_url)
        await transport.connect()
        await session_registry.add_session(transport.session_id, transport)

        asyncio.create_task(session_registry.respond(None, user, session_id=transport.session_id, base_url=base_url))

        response = await transport.create_sse_response(request)
        tasks = BackgroundTasks()
        tasks.add_task(session_registry.remove_session, transport.session_id)
        response.background = tasks
        logger.info("SSE connection established: %s", transport.session_id)
        return response
    except Exception as e:
        logger.error("SSE connection error: %s", e)
        raise HTTPException(status_code=500, detail="SSE connection failed")


@utility_router.post("/message")
async def utility_message_endpoint(request: Request, user: str = Depends(require_auth)):
    """
    Handle a JSON-RPC message directed to a specific SSE session.

    Args:
        request (Request): Incoming request containing the JSON-RPC payload.
        user (str): Authenticated user.

    Returns:
        JSONResponse: ``{"status": "success"}`` with HTTP 202 on success.

    Raises:
        HTTPException: * **400 Bad Request** - ``session_id`` query parameter is missing or the payload cannot be parsed as JSON.
            * **500 Internal Server Error** - An unexpected error occurs while broadcasting the message.
    """
    try:
        logger.debug("User %s sent a message to SSE session", user)

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
        logger.error("Invalid message format: %s", e)
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Message handling error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to process message")


@utility_router.post("/logging/setLevel")
async def set_log_level(request: Request, user: str = Depends(require_auth)) -> None:
    """
    Update the server's log level at runtime.

    Args:
        request: HTTP request with log level JSON body.
        user: Authenticated user.

    Returns:
        None
    """
    logger.debug(f"User {user} requested to set log level")
    body = await request.json()
    level = LogLevel(body["level"])
    await logging_service.set_level(level)
    return None
