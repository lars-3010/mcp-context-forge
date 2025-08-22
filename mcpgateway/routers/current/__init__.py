# For test router instances -> tests/unit/mcpgateway/test_coverage_push

from mcpgateway.routers.v1.protocol import protocol_router
from mcpgateway.routers.v1.resources import resource_router
from mcpgateway.routers.v1.root import root_router
from mcpgateway.routers.v1.tool import tool_router
from mcpgateway.routers.v1.export_import import export_import_router
from mcpgateway.routers.v1.prompts import prompt_router
from mcpgateway.routers.v1.gateway import gateway_router
from mcpgateway.routers.v1.prompts import prompt_router

# To configure Root-level RPC endpoints
# from mcpgateway.routers.v1.utility import handle_rpc

# For utility router
from mcpgateway.routers.v1.protocol import initialize

# For test_proxy_auth.py
from mcpgateway.routers.v1.utility import websocket_endpoint, handle_rpc
