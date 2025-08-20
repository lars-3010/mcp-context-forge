"""Route setup and configuration module.

This module provides centralized route configuration functions for the MCP Gateway.
It organizes API endpoints into versioned groups and handles legacy route deprecation.
"""

# Third-Party
from fastapi import FastAPI

# First-Party
from mcpgateway.routers.v1.gateway import gateway_router
from mcpgateway.routers.v1.metrics import metrics_router
from mcpgateway.routers.v1.prompts import prompt_router

# First-party
from mcpgateway.routers.v1.protocol import protocol_router
from mcpgateway.routers.v1.resources import resource_router
from mcpgateway.routers.v1.root import root_router
from mcpgateway.routers.v1.servers import server_router
from mcpgateway.routers.v1.tag import tag_router
from mcpgateway.routers.v1.tool import tool_router
from mcpgateway.routers.v1.utility import utility_router
from mcpgateway.version import router as version_router
from mcpgateway.routers.v1.admin import admin_router


def setup_v1_routes(app: FastAPI) -> None:
    """Configure all v1 API routes.

    Args:
        app: FastAPI application instance to configure
    """
    app.include_router(tool_router)
    app.include_router(protocol_router)
    app.include_router(resource_router)
    app.include_router(prompt_router)
    app.include_router(gateway_router)
    app.include_router(root_router)
    app.include_router(utility_router)
    app.include_router(server_router)
    app.include_router(metrics_router)
    app.include_router(tag_router)


def setup_version_routes(app: FastAPI) -> None:
    """Configure version endpoint.

    Args:
        app: FastAPI application instance to configure
    """
    app.include_router(version_router)


def setup_experimental_routes(app: FastAPI) -> None:
    """Configure experimental API routes.

    Args:
        app: FastAPI application instance to configure
    """
    # Register experimental routers here



def setup_legacy_deprecation_routes(app: FastAPI) -> None:
    """Configure legacy route deprecation warnings.

    Args:
        app: FastAPI application instance to configure
    """

    # Legacy routes are now handled by middleware instead of conflicting endpoints
