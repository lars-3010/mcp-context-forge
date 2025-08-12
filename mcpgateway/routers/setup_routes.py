from fastapi import FastAPI

# First-party
from mcpgateway.routers.v1.protocol import protocol_router
from mcpgateway.routers.v1.tool import tool_router
from mcpgateway.routers.v1.resources import resource_router
from mcpgateway.routers.v1.prompts import prompt_router
from mcpgateway.routers.v1.gateway import gateway_router
from mcpgateway.routers.v1.root import root_router
from mcpgateway.routers.v1.utility import utility_router
from mcpgateway.routers.v1.servers import server_router
from mcpgateway.routers.v1.metrics import metrics_router
from mcpgateway.routers.v1.tag import tag_router


def setup_v1_routes(app: FastAPI):
    # All v1 routes
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


def setup_experimental_routes(app: FastAPI):
    # Register experimental routers here
    pass

def setup_legacy_deprecation_routes(app: FastAPI):
    # Optionally warn or redirect for legacy endpoints
    @app.get("/tools")
    def legacy_tools():
        return {"warning": "Legacy route — please use /v1/tools"}
