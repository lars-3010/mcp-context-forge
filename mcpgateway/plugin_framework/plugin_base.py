# -*- coding: utf-8 -*-
"""
Plugin Framework for MCP Gateway

This module provides the core plugin infrastructure including:
- Hook points for all major operations
- Plugin lifecycle management
- Execution context and state management
- Priority-based execution ordering
"""

# Standard
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import auto, Enum
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class HookType(Enum):
    """Enumeration of all available hook points in MCP Gateway"""

    # Server hooks
    SERVER_PRE_REGISTER = auto()
    SERVER_POST_REGISTER = auto()

    # Tool hooks
    TOOL_PRE_INVOKE = auto()
    TOOL_POST_INVOKE = auto()

    # Prompt hooks
    PROMPT_PRE_FETCH = auto()
    PROMPT_POST_FETCH = auto()

    # Resource hooks
    RESOURCE_PRE_FETCH = auto()
    RESOURCE_POST_FETCH = auto()

    # Auth hooks
    AUTH_PRE_CHECK = auto()
    AUTH_POST_CHECK = auto()

    # Federation hooks
    FEDERATION_PRE_SYNC = auto()
    FEDERATION_POST_SYNC = auto()

    # Request/Response hooks
    REQUEST_PRE_PROCESS = auto()
    REQUEST_POST_PROCESS = auto()


class PluginExecutionMode(Enum):
    """Plugin execution modes"""

    ENFORCING = "enforcing"  # Block on failure
    PERMISSIVE = "permissive"  # Log but don't block
    DISABLED = "disabled"  # Skip entirely


class PluginScope(Enum):
    """Plugin scope levels"""

    GLOBAL = "global"
    TENANT = "tenant"
    SERVER = "server"
    TOOL = "tool"
    USER = "user"


@dataclass
class PluginContext:
    """Context passed to plugins during execution"""

    request_id: str
    user: Optional[str] = None
    tenant_id: Optional[str] = None
    server_id: Optional[str] = None
    tool_name: Optional[str] = None
    hook_type: Optional[HookType] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    state: Dict[str, Any] = field(default_factory=dict)  # Shared state between hooks
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_state(self, key: str, default: Any = None) -> Any:
        """Get value from shared state"""
        return self.state.get(key, default)

    def set_state(self, key: str, value: Any) -> None:
        """Set value in shared state"""
        self.state[key] = value

    async def cleanup(self):
        """Cleanup context resources"""
        self.state.clear()
        self.metadata.clear()


@dataclass
class PluginResult:
    """Result returned by plugin execution"""

    success: bool = True
    continue_processing: bool = True
    modified_payload: Optional[Any] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def should_block(self) -> bool:
        """Check if this result should block further processing"""
        return not self.continue_processing or not self.success


class PluginCondition:
    """Conditions for when a plugin should execute"""

    def __init__(self, server_ids: Optional[Set[str]] = None, tool_names: Optional[Set[str]] = None, user_patterns: Optional[List[str]] = None, tenant_ids: Optional[Set[str]] = None):
        self.server_ids = server_ids or set()
        self.tool_names = tool_names or set()
        self.user_patterns = user_patterns or []
        self.tenant_ids = tenant_ids or set()

    def matches(self, context: PluginContext) -> bool:
        """Check if conditions match the current context"""
        # Check server ID
        if self.server_ids and context.server_id not in self.server_ids:
            return False

        # Check tool name
        if self.tool_names and context.tool_name not in self.tool_names:
            return False

        # Check tenant ID
        if self.tenant_ids and context.tenant_id not in self.tenant_ids:
            return False

        # Check user patterns (simple contains check, could be regex)
        if self.user_patterns and context.user:
            if not any(pattern in context.user for pattern in self.user_patterns):
                return False

        return True


class BasePlugin(ABC):
    """Base class for all plugins"""

    # Plugin metadata
    name: str = "BasePlugin"
    version: str = "1.0.0"
    description: str = "Base plugin class"
    author: str = "Unknown"

    # Hook types this plugin implements
    hooks: Set[HookType] = set()

    # Execution priority (lower = higher priority)
    priority: int = 100

    # Plugin requirements
    requires: List[str] = []  # Platform dependencies

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.mode = PluginExecutionMode(config.get("mode", "enforcing"))
        self.condition = self._parse_conditions(config.get("conditions", {}))
        self._initialized = False

    def _parse_conditions(self, conditions: Dict[str, Any]) -> PluginCondition:
        """Parse plugin conditions from config"""
        return PluginCondition(
            server_ids=set(conditions.get("server_ids", [])),
            tool_names=set(conditions.get("tool_names", [])),
            user_patterns=conditions.get("user_patterns", []),
            tenant_ids=set(conditions.get("tenant_ids", [])),
        )

    async def initialize(self) -> None:
        """Initialize the plugin"""
        self._initialized = True
        logger.info(f"Plugin {self.name} initialized")

    async def shutdown(self) -> None:
        """Shutdown the plugin"""
        self._initialized = False
        logger.info(f"Plugin {self.name} shutdown")

    async def health_check(self) -> bool:
        """Check if plugin is healthy"""
        return self._initialized

    def should_execute(self, context: PluginContext) -> bool:
        """Check if plugin should execute in current context"""
        if not self.enabled or self.mode == PluginExecutionMode.DISABLED:
            return False

        if context.hook_type not in self.hooks:
            return False

        return self.condition.matches(context)

    @abstractmethod
    async def execute(self, hook_type: HookType, payload: Any, context: PluginContext) -> PluginResult:
        """Execute the plugin for the given hook"""

    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "hooks": [h.name for h in self.hooks],
            "priority": self.priority,
            "requires": self.requires,
            "enabled": self.enabled,
            "mode": self.mode.value,
        }


class PrePostProcessPlugin(BasePlugin):
    """Base class for plugins that need pre/post processing pairs"""

    async def execute(self, hook_type: HookType, payload: Any, context: PluginContext) -> PluginResult:
        """Route to appropriate pre/post method"""
        if hook_type.name.endswith("_PRE_") or "_PRE_" in hook_type.name:
            return await self.preprocess(hook_type, payload, context)
        elif hook_type.name.endswith("_POST_") or "_POST_" in hook_type.name:
            return await self.postprocess(hook_type, payload, context)
        else:
            return PluginResult(success=False, error_message=f"Unknown hook type: {hook_type}")

    @abstractmethod
    async def preprocess(self, hook_type: HookType, payload: Any, context: PluginContext) -> PluginResult:
        """Pre-processing logic"""

    @abstractmethod
    async def postprocess(self, hook_type: HookType, payload: Any, context: PluginContext) -> PluginResult:
        """Post-processing logic"""


class ExternalServicePlugin(BasePlugin):
    """Base class for plugins that call external microservices"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.service_url = config.get("service_url")
        self.auth_config = config.get("auth", {})
        self.timeout = config.get("timeout", 30)
        self.retry_config = config.get("retry", {"max_attempts": 3, "backoff": 1.0})

    async def call_external_service(self, endpoint: str, payload: Any, method: str = "POST") -> Dict[str, Any]:
        """Make authenticated call to external service with retry logic"""
        # This would use your ResilientHttpClient
        # Implementation details would go here
        raise NotImplementedError("External service calls need to be implemented")


class CompositePlugin(BasePlugin):
    """Plugin that combines multiple plugins into a single unit"""

    def __init__(self, config: Dict[str, Any], plugins: List[BasePlugin]):
        super().__init__(config)
        self.plugins = sorted(plugins, key=lambda p: p.priority)
        # Combine all hooks from sub-plugins
        self.hooks = set().union(*[p.hooks for p in plugins])

    async def execute(self, hook_type: HookType, payload: Any, context: PluginContext) -> PluginResult:
        """Execute all sub-plugins in order"""
        current_payload = payload

        for plugin in self.plugins:
            if not plugin.should_execute(context):
                continue

            result = await plugin.execute(hook_type, current_payload, context)

            if result.modified_payload is not None:
                current_payload = result.modified_payload

            if result.should_block:
                return result

        return PluginResult(success=True, modified_payload=current_payload)


# Decorator for easy hook registration
def hook(hook_type: HookType, priority: int = 100):
    """Decorator to register a function as a hook handler"""

    def decorator(func: Callable[[Any, PluginContext], Awaitable[PluginResult]]):
        if not hasattr(func, "_hooks"):
            func._hooks = {}
        func._hooks[hook_type] = priority
        return func

    return decorator


class DecoratorPlugin(BasePlugin):
    """Plugin created from decorated functions"""

    def __init__(self, config: Dict[str, Any], handlers: Dict[HookType, Callable]):
        super().__init__(config)
        self.handlers = handlers
        self.hooks = set(handlers.keys())

    async def execute(self, hook_type: HookType, payload: Any, context: PluginContext) -> PluginResult:
        if hook_type not in self.handlers:
            return PluginResult()

        handler = self.handlers[hook_type]
        return await handler(payload, context)


# Priority bands for execution order
PRIORITY_BANDS = {
    "authentication": range(0, 100),  # 0-99
    "input_validation": range(100, 200),  # 100-199
    "business_logic": range(200, 300),  # 200-299
    "output_filtering": range(300, 400),  # 300-399
    "logging": range(400, 500),  # 400-499
}


def get_priority_band(priority: int) -> str:
    """Get the priority band name for a given priority"""
    for band_name, band_range in PRIORITY_BANDS.items():
        if priority in band_range:
            return band_name
    return "custom"
