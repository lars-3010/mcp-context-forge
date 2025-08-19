"""Dependency injection module for MCP Gateway services.

Provides singleton service instances using a factory pattern to ensure
consistent service lifecycle management across the application.
"""

# First-Party
from mcpgateway.cache import ResourceCache
from mcpgateway.config import settings
from mcpgateway.handlers.sampling import SamplingHandler
from mcpgateway.registry import session_registry
from mcpgateway.services.completion_service import CompletionService
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import ServerService
from mcpgateway.services.tag_service import TagService
from mcpgateway.services.tool_service import ToolService
from mcpgateway.transports.streamablehttp_transport import SessionManagerWrapper

# Singleton instances
_services = {}


def get_completion_service() -> CompletionService:
    """Get singleton completion service instance.

    Returns:
        CompletionService: The singleton completion service instance.
    """
    if "completion" not in _services:
        _services["completion"] = CompletionService()
    return _services["completion"]


def get_gateway_service() -> GatewayService:
    """Get singleton gateway service instance.

    Returns:
        GatewayService: The singleton gateway service instance.
    """
    if "gateway" not in _services:
        _services["gateway"] = GatewayService()
    return _services["gateway"]


def get_logging_service() -> LoggingService:
    """Get singleton logging service instance.

    Returns:
        LoggingService: The singleton logging service instance.
    """
    if "logging" not in _services:
        _services["logging"] = LoggingService()
    return _services["logging"]


def get_prompt_service() -> PromptService:
    """Get singleton prompt service instance.

    Returns:
        PromptService: The singleton prompt service instance.
    """
    if "prompt" not in _services:
        _services["prompt"] = PromptService()
    return _services["prompt"]


def get_resource_service() -> ResourceService:
    """Get singleton resource service instance.

    Returns:
        ResourceService: The singleton resource service instance.
    """
    if "resource" not in _services:
        _services["resource"] = ResourceService()
    return _services["resource"]


def get_root_service() -> RootService:
    """Get singleton root service instance.

    Returns:
        RootService: The singleton root service instance.
    """
    if "root" not in _services:
        _services["root"] = RootService()
    return _services["root"]


def get_server_service() -> ServerService:
    """Get singleton server service instance.

    Returns:
        ServerService: The singleton server service instance.
    """
    if "server" not in _services:
        _services["server"] = ServerService()
    return _services["server"]


def get_tag_service() -> TagService:
    """Get singleton tag service instance.

    Returns:
        TagService: The singleton tag service instance.
    """
    if "tag" not in _services:
        _services["tag"] = TagService()
    return _services["tag"]


def get_tool_service() -> ToolService:
    """Get singleton tool service instance.

    Returns:
        ToolService: The singleton tool service instance.
    """
    if "tool" not in _services:
        _services["tool"] = ToolService()
    return _services["tool"]


def get_sampling_handler() -> SamplingHandler:
    """Get singleton sampling handler instance.

    Returns:
        SamplingHandler: The singleton sampling handler instance.
    """
    if "sampling" not in _services:
        _services["sampling"] = SamplingHandler()
    return _services["sampling"]


def get_resource_cache() -> ResourceCache:
    """Get singleton resource cache instance.

    Returns:
        ResourceCache: The singleton resource cache instance.
    """
    if "resource_cache" not in _services:
        _services["resource_cache"] = ResourceCache(max_size=settings.resource_cache_size, ttl=settings.resource_cache_ttl)
    return _services["resource_cache"]


def get_streamable_http_session() -> SessionManagerWrapper:
    """Get singleton streamable HTTP session instance.

    Returns:
        SessionManagerWrapper: The singleton streamable HTTP session instance.
    """
    if "streamable_http_session" not in _services:
        _services["streamable_http_session"] = SessionManagerWrapper()
    return _services["streamable_http_session"]


def get_session_registry():
    """Get singleton session registry instance.

    Returns:
        The singleton session registry instance.
    """
    return session_registry
