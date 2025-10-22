"""
Passthrough router for REST tools with pre/post plugin hooks.
"""
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.status import HTTP_502_BAD_GATEWAY, HTTP_504_GATEWAY_TIMEOUT, HTTP_403_FORBIDDEN, HTTP_422_UNPROCESSABLE_ENTITY
from mcpgateway.services.tool_service import ToolService
from mcpgateway.services.plugin_service import PluginService, get_plugin_service
from mcpgateway.config import config as gateway_config
from mcpgateway.auth import get_current_user, require_jwt_auth
from mcpgateway.observability import trace_passthrough
import httpx
import asyncio
import logging


# Instantiate services (in real app, use dependency injection or app state)
tool_service = ToolService()
plugin_service = get_plugin_service()
router = APIRouter()


@router.api_route("/passthrough/{namespace}/{tool_id}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@trace_passthrough
async def passthrough_endpoint(
    namespace: str,
    tool_id: str,
    path: str = "",
    request: Request = None,
    user=Depends(require_jwt_auth),
):
    # 1. Resolve tool and validate expose_passthrough
    # Use tool_service to get tool (adjust as needed for your DB/session context)
    tool = tool_service.get_tool_by_namespace_and_id(namespace, tool_id) if hasattr(tool_service, 'get_tool_by_namespace_and_id') else None
    if not tool or not getattr(tool, "expose_passthrough", False):
        raise HTTPException(status_code=404, detail="Tool not found or passthrough not enabled")

    # Restrict allowed HTTP methods per tool config (from tool.method or allowed_methods)
    allowed_methods = None
    if hasattr(tool, "allowed_methods") and tool.allowed_methods:
        allowed_methods = [m.upper() for m in tool.allowed_methods]
    elif hasattr(tool, "method") and tool.method:
        allowed_methods = [str(tool.method).upper()]
    if allowed_methods and request.method.upper() not in allowed_methods:
        raise HTTPException(status_code=405, detail=f"Method {request.method} not allowed for this tool")

    # 2. Build upstream URL and map request (path/query/header/body)
    base_url = tool.base_url.rstrip("/")
    path_template = getattr(tool, "path_template", "").lstrip("/")
    if "{path}" in path_template:
        mapped_path = path_template.replace("{path}", path)
    else:
        mapped_path = f"{path_template}/{path}" if path_template else path
    full_path = f"{base_url}/{mapped_path}".rstrip("/")

    # SSRF/allowlist protections
    passthrough_cfg = getattr(gateway_config, "passthrough", {})
    allowlist = getattr(tool, "allowlist", None) or passthrough_cfg.get("allowlist") or passthrough_cfg.get("default_allowlist", [])
    if allowlist:
        from urllib.parse import urlparse
        parsed = urlparse(full_path)
        allowed = any(parsed.hostname and parsed.hostname.endswith(host) for host in allowlist)
        if not allowed:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Upstream host not allowed by allowlist policy")

    # Query mapping (from tool.query_mapping or query_map)
    query_params = dict(request.query_params)
    query_mapping = getattr(tool, "query_mapping", None) or getattr(tool, "query_map", None)
    if query_mapping:
        mapped_query = {query_mapping.get(k, k): v for k, v in query_params.items()}
    else:
        mapped_query = query_params

    # Header mapping (from tool.header_mapping or header_map)
    headers = dict(request.headers)
    header_mapping = getattr(tool, "header_mapping", None) or getattr(tool, "header_map", None)
    if header_mapping:
        mapped_headers = {header_mapping.get(k, k): v for k, v in headers.items()}
    else:
        mapped_headers = headers

    try:
        body = await request.body()
    except Exception:
        body = None
    if hasattr(tool, "body_map") and callable(tool.body_map):
        mapped_body = tool.body_map(body)
    else:
        mapped_body = body

    # 3. Run passthrough pre-plugins (tool-level or passthrough config default)
    context = {"user": user, "tool": tool, "namespace": namespace}
    plugin_chain_pre = getattr(tool, "plugin_chain_pre", None)
    if not plugin_chain_pre:
        plugin_chain_pre = passthrough_cfg.get("default_plugin_chains", {}).get("pre", [])
    try:
        await run_passthrough_plugin_chain(plugin_chain_pre, "on_passthrough_request", context, request)
    except Exception as e:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail=str(e))

    # 4. Forward request to upstream
    timeout = getattr(tool, "timeout_ms", None)
    if timeout is None:
        timeout = passthrough_cfg.get("default_timeout_ms", 20000)
    timeout = timeout / 1000.0
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            upstream_response = await client.request(
                request.method,
                full_path,
                params=mapped_query,
                content=mapped_body,
                headers=mapped_headers,
                follow_redirects=True,
            )
        except httpx.TimeoutException:
            raise HTTPException(status_code=HTTP_504_GATEWAY_TIMEOUT, detail="Upstream timeout")
        except Exception as e:
            logging.error(f"Upstream error: {e}")
            raise HTTPException(status_code=HTTP_502_BAD_GATEWAY, detail=f"Upstream error: {e}")

    # 5. Run passthrough post-plugins (tool-level or passthrough config default)
    plugin_chain_post = getattr(tool, "plugin_chain_post", None)
    if not plugin_chain_post:
        plugin_chain_post = passthrough_cfg.get("default_plugin_chains", {}).get("post", [])
    try:
        await run_passthrough_plugin_chain(plugin_chain_post, "on_passthrough_response", context, request, upstream_response)
    except Exception as e:
        raise HTTPException(status_code=HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
async def run_passthrough_plugin_chain(plugin_names, hook, context, *args):
    """
    Run passthrough plugin chain for the given hook (pre or post).
    This is a stub: you must implement plugin lookup and invocation logic for passthrough hooks.
    """
    # Example: for each plugin name, get plugin instance and call the hook if implemented
    for name in plugin_names:
        plugin = plugin_service.get_plugin_manager().get_plugin(name)
        if not plugin:
            continue
        hook_fn = getattr(plugin, hook, None)
        if hook_fn and callable(hook_fn):
            # Await the hook, passing context and args
            await hook_fn(context, *args)

    # 6. Return response with correct status, headers, and body
    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=dict(upstream_response.headers),
        media_type=upstream_response.headers.get("content-type")
    )
