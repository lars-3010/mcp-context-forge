"""
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

MCP Gateway - Tools API Router.

This module provides REST API endpoints for managing tools in the MCP Gateway.
Tools are executable functions that can be invoked by MCP clients with input validation,
retry logic, and comprehensive error handling.

Features and Responsibilities:
- CRUD operations for tool management (create, read, update, delete)
- Tool invocation with parameter validation and timeout handling
- Status management (activate/deactivate tools)
- JSONPath filtering and response transformation
- Tag-based filtering and pagination support
- Conflict resolution for duplicate tool names
- Comprehensive error handling with proper HTTP status codes

Endpoints:
- GET /tools: List all tools with optional filtering and JSONPath transformation
- POST /tools: Create new tool with validation
- GET /tools/{id}: Retrieve specific tool with optional JSONPath filtering
- PUT /tools/{id}: Update existing tool
- DELETE /tools/{id}: Permanently delete tool
- POST /tools/{id}/toggle: Activate/deactivate tool

Parameters:
- All endpoints require authentication via JWT Bearer token or Basic Auth
- JSONPath modifiers enable response filtering and transformation
- Tag filtering supports comma-separated lists
- Status toggles support activation state and reachability flags

Returns:
- List endpoints return arrays of ToolRead objects or JSONPath-transformed data
- CRUD operations return individual ToolRead objects
- Delete operations return success confirmation messages
- Toggle operations return status with updated tool data
"""

# Standard
from typing import Any, Dict, List, Optional, Union

# First-Party
from mcpgateway.services.tool_service import (
    ToolError,
    ToolNameConflictError,
    ToolService,)
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.db import get_db
from mcpgateway.schemas import (
    JsonPathModifier,
    ToolCreate,
    ToolRead,
    ToolUpdate,
)
from mcpgateway.config import jsonpath_modifier
from mcpgateway.utils.verify_credentials import require_auth

# Third-Party
from fastapi import (
    APIRouter,)

from sqlalchemy.orm import Session
from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    status,
)

# Import dependency injection functions
from mcpgateway.dependencies import get_tool_service

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger("tool routes")

# Initialize services
tool_service = get_tool_service()

# Create API router
tool_router = APIRouter(prefix="/tools", tags=["Tools"])

@tool_router.get("", response_model=Union[List[ToolRead], List[Dict], Dict, List])
@tool_router.get("/", response_model=Union[List[ToolRead], List[Dict], Dict, List])
async def list_tools(
    cursor: Optional[str] = None,
    include_inactive: bool = False,
    tags: Optional[str] = None,
    db: Session = Depends(get_db),
    apijsonpath: JsonPathModifier = Body(None),
    _: str = Depends(require_auth),
) -> Union[List[ToolRead], List[Dict], Dict]: 
    """List all registered tools with pagination support.

    Args:
        cursor: Pagination cursor for fetching the next set of results
        include_inactive: Whether to include inactive tools in the results
        tags: Comma-separated list of tags to filter by (e.g., "api,data")
        db: Database session
        apijsonpath: JSON path modifier to filter or transform the response
        _: Authenticated user

    Returns:
        List of tools or modified result based on jsonpath
    """
    print(f"v1 tools")

    # Parse tags parameter if provided
    tags_list = None
    if tags:
        tags_list = [tag.strip() for tag in tags.split(",") if tag.strip()]

    # For now just pass the cursor parameter even if not used
    data = await tool_service.list_tools(db, cursor=cursor, include_inactive=include_inactive, tags=tags_list)

    if apijsonpath is None:
        return data

    tools_dict_list = [tool.to_dict(use_alias=True) for tool in data]

    return jsonpath_modifier(tools_dict_list, apijsonpath.jsonpath, apijsonpath.mapping)


@tool_router.post("", response_model=ToolRead)
@tool_router.post("/", response_model=ToolRead)
async def create_tool(tool: ToolCreate, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> ToolRead:
    """
    Creates a new tool in the system.

    Args:
        tool (ToolCreate): The data needed to create the tool.
        db (Session): The database session dependency.
        user (str): The authenticated user making the request.

    Returns:
        ToolRead: The created tool data.

    Raises:
        HTTPException: If the tool name already exists or other validation errors occur.
    """
    
    try:
        logger.debug(f"User {user} is creating a new tool")
        return await tool_service.register_tool(db, tool)
    except ToolNameConflictError as e:
        if not e.enabled and e.tool_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Tool name already exists but is inactive. Consider activating it with ID: {e.tool_id}",
            )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ToolError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@tool_router.get("/{tool_id}", response_model=Union[ToolRead, Dict])
async def get_tool(
    tool_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
    apijsonpath: JsonPathModifier = Body(None),
) -> Union[ToolRead, Dict]:
    """
    Retrieve a tool by ID, optionally applying a JSONPath post-filter.

    Args:
        tool_id: The numeric ID of the tool.
        db:     Active SQLAlchemy session (dependency).
        user:   Authenticated username (dependency).
        apijsonpath: Optional JSON-Path modifier supplied in the body.

    Returns:
        The raw ``ToolRead`` model **or** a JSON-transformed ``dict`` if
        a JSONPath filter/mapping was supplied.

    Raises:
        HTTPException: If the tool does not exist or the transformation fails.
    """
    try:
        logger.debug(f"User {user} is retrieving tool with ID {tool_id}")
        data = await tool_service.get_tool(db, tool_id)
        if apijsonpath is None:
            return data

        data_dict = data.to_dict(use_alias=True)

        return jsonpath_modifier(data_dict, apijsonpath.jsonpath, apijsonpath.mapping)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@tool_router.put("/{tool_id}", response_model=ToolRead)
async def update_tool(
    tool_id: str,
    tool: ToolUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> ToolRead:
    """
    Updates an existing tool with new data.

    Args:
        tool_id (str): The ID of the tool to update.
        tool (ToolUpdate): The updated tool information.
        db (Session): The database session dependency.
        user (str): The authenticated user making the request.

    Returns:
        ToolRead: The updated tool data.

    Raises:
        HTTPException: If an error occurs during the update.
    """
    try:
        logger.debug(f"User {user} is updating tool with ID {tool_id}")
        return await tool_service.update_tool(db, tool_id, tool)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@tool_router.delete("/{tool_id}")
async def delete_tool(tool_id: str, db: Session = Depends(get_db), user: str = Depends(require_auth)) -> Dict[str, str]:
    """
    Permanently deletes a tool by ID.

    Args:
        tool_id (str): The ID of the tool to delete.
        db (Session): The database session dependency.
        user (str): The authenticated user making the request.

    Returns:
        Dict[str, str]: A confirmation message upon successful deletion.

    Raises:
        HTTPException: If an error occurs during deletion.
    """
    try:
        logger.debug(f"User {user} is deleting tool with ID {tool_id}")
        await tool_service.delete_tool(db, tool_id)
        return {"status": "success", "message": f"Tool {tool_id} permanently deleted"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@tool_router.post("/{tool_id}/toggle")
async def toggle_tool_status(
    tool_id: str,
    activate: bool = True,
    db: Session = Depends(get_db),
    user: str = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Activates or deactivates a tool.

    Args:
        tool_id (str): The ID of the tool to toggle.
        activate (bool): Whether to activate (`True`) or deactivate (`False`) the tool.
        db (Session): The database session dependency.
        user (str): The authenticated user making the request.

    Returns:
        Dict[str, Any]: The status, message, and updated tool data.

    Raises:
        HTTPException: If an error occurs during status toggling.
    """
    try:
        logger.debug(f"User {user} is toggling tool with ID {tool_id} to {'active' if activate else 'inactive'}")
        tool = await tool_service.toggle_tool_status(db, tool_id, activate, reachable=activate)
        return {
            "status": "success",
            "message": f"Tool {tool_id} {'activated' if activate else 'deactivated'}",
            "tool": tool.model_dump(),
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
