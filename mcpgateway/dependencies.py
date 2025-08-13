from mcpgateway.services.completion_service import CompletionService
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.root_service import RootService
from mcpgateway.services.server_service import ServerService
from mcpgateway.services.tag_service import TagService
from mcpgateway.services.tool_service import ToolService
from mcpgateway.handlers.sampling import SamplingHandler
from mcpgateway.transports.streamablehttp_transport import SessionManagerWrapper
from mcpgateway.cache import ResourceCache
from mcpgateway.config import settings

# Singleton instances
_services = {}

def get_completion_service() -> CompletionService:
    if 'completion' not in _services:
        _services['completion'] = CompletionService()
    return _services['completion']

def get_gateway_service() -> GatewayService:
    if 'gateway' not in _services:
        _services['gateway'] = GatewayService()
    return _services['gateway']

def get_logging_service() -> LoggingService:
    if 'logging' not in _services:
        _services['logging'] = LoggingService()
    return _services['logging']

def get_prompt_service() -> PromptService:
    if 'prompt' not in _services:
        _services['prompt'] = PromptService()
    return _services['prompt']

def get_resource_service() -> ResourceService:
    if 'resource' not in _services:
        _services['resource'] = ResourceService()
    return _services['resource']

def get_root_service() -> RootService:
    if 'root' not in _services:
        _services['root'] = RootService()
    return _services['root']

def get_server_service() -> ServerService:
    if 'server' not in _services:
        _services['server'] = ServerService()
    return _services['server']

def get_tag_service() -> TagService:
    if 'tag' not in _services:
        _services['tag'] = TagService()
    return _services['tag']

def get_tool_service() -> ToolService:
    if 'tool' not in _services:
        _services['tool'] = ToolService()
    return _services['tool']

def get_sampling_handler() -> SamplingHandler:
    if 'sampling' not in _services:
        _services['sampling'] = SamplingHandler()
    return _services['sampling']

def get_resource_cache() -> ResourceCache:
    if 'resource_cache' not in _services:
        _services['resource_cache'] = ResourceCache(
            max_size=settings.resource_cache_size, 
            ttl=settings.resource_cache_ttl
        )
    return _services['resource_cache']

def get_streamable_http_session() -> SessionManagerWrapper:
    if 'streamable_http_session' not in _services:
        _services['streamable_http_session'] = SessionManagerWrapper()
    return _services['streamable_http_session']