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
    HTTPException,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

# First-Party
from mcpgateway import __version__
from mcpgateway.bootstrap_db import main as bootstrap_db
from mcpgateway.config import jsonpath_modifier, settings
from mcpgateway.db import refresh_slugs_on_startup, SessionLocal, get_db
from mcpgateway.models import (
    InitializeResult,
    LogLevel,
)
from mcpgateway.services.completion_service import CompletionService
from mcpgateway.handlers.sampling import SamplingHandler
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.utils.verify_credentials import require_auth


# Import the admin routes from the new module
from mcpgateway.version import router as version_router

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("protocol routes")


completion_service = CompletionService()
sampling_handler = SamplingHandler()

# Create API router
protocol_router = APIRouter(prefix="/protocol", tags=["Protocol"])


# Protocol APIs #
@protocol_router.post("/initialize")
async def initialize(request: Request, user: str = Depends(require_auth)) -> InitializeResult:
    """
    Initialize a protocol.

    This endpoint handles the initialization process of a protocol by accepting
    a JSON request body and processing it. The `require_auth` dependency ensures that
    the user is authenticated before proceeding.

    Args:
        request (Request): The incoming request object containing the JSON body.
        user (str): The authenticated user (from `require_auth` dependency).

    Returns:
        InitializeResult: The result of the initialization process.

    Raises:
        HTTPException: If the request body contains invalid JSON, a 400 Bad Request error is raised.
    """
    try:
        body = await request.json()

        logger.debug(f"Authenticated user {user} is initializing the protocol.")
        return await session_registry.handle_initialize_logic(body)

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON in request body",
        )


@protocol_router.post("/ping")
async def ping(request: Request, user: str = Depends(require_auth)) -> JSONResponse:
    """
    Handle a ping request according to the MCP specification.

    This endpoint expects a JSON-RPC request with the method "ping" and responds
    with a JSON-RPC response containing an empty result, as required by the protocol.

    Args:
        request (Request): The incoming FastAPI request.
        user (str): The authenticated user (dependency injection).

    Returns:
        JSONResponse: A JSON-RPC response with an empty result or an error response.

    Raises:
        HTTPException: If the request method is not "ping".
    """
    try:
        body: dict = await request.json()
        if body.get("method") != "ping":
            raise HTTPException(status_code=400, detail="Invalid method")
        req_id: str = body.get("id")
        logger.debug(f"Authenticated user {user} sent ping request.")
        # Return an empty result per the MCP ping specification.
        response: dict = {"jsonrpc": "2.0", "id": req_id, "result": {}}
        return JSONResponse(content=response)
    except Exception as e:
        error_response: dict = {
            "jsonrpc": "2.0",
            "id": body.get("id") if "body" in locals() else None,
            "error": {"code": -32603, "message": "Internal error", "data": str(e)},
        }
        return JSONResponse(status_code=500, content=error_response)


@protocol_router.post("/notifications")
async def handle_notification(request: Request, user: str = Depends(require_auth)) -> None:
    """
    Handles incoming notifications from clients. Depending on the notification method,
    different actions are taken (e.g., logging initialization, cancellation, or messages).

    Args:
        request (Request): The incoming request containing the notification data.
        user (str): The authenticated user making the request.
    """
    body = await request.json()
    logger.debug(f"User {user} sent a notification")
    if body.get("method") == "notifications/initialized":
        logger.info("Client initialized")
        await logging_service.notify("Client initialized", LogLevel.INFO)
    elif body.get("method") == "notifications/cancelled":
        request_id = body.get("params", {}).get("requestId")
        logger.info(f"Request cancelled: {request_id}")
        await logging_service.notify(f"Request cancelled: {request_id}", LogLevel.INFO)
    elif body.get("method") == "notifications/message":
        params = body.get("params", {})
        await logging_service.notify(
            params.get("data"),
            LogLevel(params.get("level", "info")),
            params.get("logger"),
        )


@protocol_router.post("/completion/complete")
async def handle_completion(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)):
    """
    Handles the completion of tasks by processing a completion request.

    Args:
        request (Request): The incoming request with completion data.
        db (Session): The database session used to interact with the data store.
        user (str): The authenticated user making the request.

    Returns:
        The result of the completion process.
    """
    body = await request.json()
    logger.debug(f"User {user} sent a completion request")
    return await completion_service.handle_completion(db, body)


@protocol_router.post("/sampling/createMessage")
async def handle_sampling(request: Request, db: Session = Depends(get_db), user: str = Depends(require_auth)):
    """
    Handles the creation of a new message for sampling.

    Args:
        request (Request): The incoming request with sampling data.
        db (Session): The database session used to interact with the data store.
        user (str): The authenticated user making the request.

    Returns:
        The result of the message creation process.
    """
    logger.debug(f"User {user} sent a sampling request")
    body = await request.json()
    return await sampling_handler.create_message(db, body)