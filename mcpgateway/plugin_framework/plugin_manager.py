# -*- coding: utf-8 -*-
"""
Plugin Manager for MCP Gateway

Handles plugin discovery, loading, lifecycle management, and execution orchestration.
"""

# Standard
import asyncio
from collections import defaultdict
import importlib
import inspect
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# Third-Party
import yaml

# Local
from .plugin_base import BasePlugin, ExternalServicePlugin, get_priority_band, HookType, PluginContext, PluginExecutionMode, PluginResult

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry for managing loaded plugins"""

    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        self._hooks: Dict[HookType, List[BasePlugin]] = defaultdict(list)
        self._priority_cache: Dict[HookType, List[BasePlugin]] = {}

    def register(self, plugin: BasePlugin) -> None:
        """Register a plugin"""
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin {plugin.name} already registered")

        self._plugins[plugin.name] = plugin

        # Register hooks
        for hook_type in plugin.hooks:
            self._hooks[hook_type].append(plugin)
            # Invalidate priority cache for this hook
            self._priority_cache.pop(hook_type, None)

        logger.info(f"Registered plugin: {plugin.name} with hooks: {[h.name for h in plugin.hooks]}")

    def unregister(self, plugin_name: str) -> None:
        """Unregister a plugin"""
        if plugin_name not in self._plugins:
            return

        plugin = self._plugins.pop(plugin_name)

        # Remove from hooks
        for hook_type in plugin.hooks:
            self._hooks[hook_type] = [p for p in self._hooks[hook_type] if p.name != plugin_name]
            self._priority_cache.pop(hook_type, None)

        logger.info(f"Unregistered plugin: {plugin_name}")

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name"""
        return self._plugins.get(name)

    def get_plugins_for_hook(self, hook_type: HookType) -> List[BasePlugin]:
        """Get all plugins for a specific hook, sorted by priority"""
        if hook_type not in self._priority_cache:
            plugins = sorted(self._hooks[hook_type], key=lambda p: p.priority)
            self._priority_cache[hook_type] = plugins
        return self._priority_cache[hook_type]

    def get_all_plugins(self) -> List[BasePlugin]:
        """Get all registered plugins"""
        return list(self._plugins.values())


class PluginLoader:
    """Handles plugin discovery and loading"""

    def __init__(self, plugin_dirs: List[Path]):
        self.plugin_dirs = plugin_dirs
        self._loaded_modules = {}

    async def load_plugin_from_module(self, module_path: str, class_name: str, config: Dict[str, Any]) -> BasePlugin:
        """Load a plugin from a Python module"""
        try:
            if module_path not in self._loaded_modules:
                module = importlib.import_module(module_path)
                self._loaded_modules[module_path] = module
            else:
                module = self._loaded_modules[module_path]

            plugin_class = getattr(module, class_name)

            if not issubclass(plugin_class, BasePlugin):
                raise ValueError(f"{class_name} is not a BasePlugin subclass")

            plugin = plugin_class(config)
            await plugin.initialize()

            return plugin

        except Exception as e:
            logger.error(f"Failed to load plugin {module_path}.{class_name}: {e}")
            raise

    async def load_plugin_from_file(self, file_path: Path, config: Dict[str, Any]) -> Optional[BasePlugin]:
        """Load a plugin from a Python file"""
        try:
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find all BasePlugin subclasses in the module
            plugin_classes = []
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj != BasePlugin:
                    plugin_classes.append(obj)

            if not plugin_classes:
                logger.warning(f"No plugin classes found in {file_path}")
                return None

            # Use the first plugin class found (or could be configured)
            plugin_class = plugin_classes[0]
            plugin = plugin_class(config)
            await plugin.initialize()

            return plugin

        except Exception as e:
            logger.error(f"Failed to load plugin from {file_path}: {e}")
            return None

    async def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover available plugins in plugin directories"""
        discovered = []

        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                continue

            # Look for plugin manifests
            for manifest_path in plugin_dir.glob("**/plugin-manifest.{yaml,yml,json}"):
                try:
                    with open(manifest_path) as f:
                        if manifest_path.suffix == ".json":
                            manifest = json.load(f)
                        else:
                            manifest = yaml.safe_load(f)

                    manifest["manifest_path"] = str(manifest_path)
                    discovered.append(manifest)

                except Exception as e:
                    logger.error(f"Failed to load manifest {manifest_path}: {e}")

        return discovered


class PluginManager:
    """Main plugin manager coordinating all plugin operations"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.registry = PluginRegistry()
        self.loader = PluginLoader([Path(p) for p in config.get("plugin_dirs", ["plugins/"])])
        self._initialized = False
        self._execution_stats = defaultdict(lambda: {"calls": 0, "errors": 0, "total_time": 0})

    async def initialize(self) -> None:
        """Initialize the plugin manager"""
        if self._initialized:
            return

        # Load configured plugins
        plugin_configs = self.config.get("plugins", [])
        for plugin_config in plugin_configs:
            try:
                await self.load_plugin(plugin_config)
            except Exception as e:
                logger.error(f"Failed to load plugin: {e}")
                if self.config.get("fail_on_plugin_error", False):
                    raise

        self._initialized = True
        logger.info(f"Plugin manager initialized with {len(self.registry.get_all_plugins())} plugins")

    async def shutdown(self) -> None:
        """Shutdown all plugins"""
        for plugin in self.registry.get_all_plugins():
            try:
                await plugin.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down plugin {plugin.name}: {e}")

        self._initialized = False

    async def load_plugin(self, plugin_config: Dict[str, Any]) -> BasePlugin:
        """Load a single plugin from configuration"""
        plugin_config.get("name")
        plugin_type = plugin_config.get("type", "module")

        if plugin_type == "module":
            module_path = plugin_config.get("module_path")
            class_name = plugin_config.get("class_name")
            plugin = await self.loader.load_plugin_from_module(module_path, class_name, plugin_config)
        elif plugin_type == "file":
            file_path = Path(plugin_config.get("file_path"))
            plugin = await self.loader.load_plugin_from_file(file_path, plugin_config)
        elif plugin_type == "external":
            # Create an external service plugin dynamically
            plugin = ExternalServicePlugin(plugin_config)
            await plugin.initialize()
        else:
            raise ValueError(f"Unknown plugin type: {plugin_type}")

        if plugin:
            self.registry.register(plugin)

        return plugin

    async def execute_hook(self, hook_type: HookType, payload: Any, context: PluginContext) -> PluginResult:
        """Execute all plugins for a specific hook"""
        plugins = self.registry.get_plugins_for_hook(hook_type)

        if not plugins:
            return PluginResult(success=True, modified_payload=payload)

        # Set hook type in context
        context.hook_type = hook_type

        # Track execution by priority band
        bands = defaultdict(list)
        for plugin in plugins:
            band = get_priority_band(plugin.priority)
            bands[band].append(plugin)

        current_payload = payload
        combined_metadata = {}

        # Execute plugins by priority band
        for band_name in ["authentication", "input_validation", "business_logic", "output_filtering", "logging", "custom"]:
            if band_name not in bands:
                continue

            # Execute plugins in parallel within the same priority band
            band_plugins = bands[band_name]
            if self.config.get("parallel_execution_within_band", True):
                results = await self._execute_plugins_parallel(band_plugins, hook_type, current_payload, context)
            else:
                results = await self._execute_plugins_sequential(band_plugins, hook_type, current_payload, context)

            # Process results
            for plugin, result in results:
                if result.metadata:
                    combined_metadata.update(result.metadata)

                if result.modified_payload is not None:
                    current_payload = result.modified_payload

                if result.should_block:
                    # Check execution mode
                    if plugin.mode == PluginExecutionMode.ENFORCING:
                        return PluginResult(
                            success=False, continue_processing=False, modified_payload=current_payload, error_message=result.error_message, error_code=result.error_code, metadata=combined_metadata
                        )
                    elif plugin.mode == PluginExecutionMode.PERMISSIVE:
                        logger.warning(f"Plugin {plugin.name} would block (permissive mode): " f"{result.error_message}")

        return PluginResult(success=True, modified_payload=current_payload, metadata=combined_metadata)

    async def _execute_plugins_sequential(self, plugins: List[BasePlugin], hook_type: HookType, payload: Any, context: PluginContext) -> List[tuple]:
        """Execute plugins sequentially"""
        results = []
        current_payload = payload

        for plugin in plugins:
            if not plugin.should_execute(context):
                continue

            result = await self._execute_single_plugin(plugin, hook_type, current_payload, context)
            results.append((plugin, result))

            if result.modified_payload is not None:
                current_payload = result.modified_payload

            if result.should_block and plugin.mode == PluginExecutionMode.ENFORCING:
                break

        return results

    async def _execute_plugins_parallel(self, plugins: List[BasePlugin], hook_type: HookType, payload: Any, context: PluginContext) -> List[tuple]:
        """Execute plugins in parallel"""
        tasks = []

        for plugin in plugins:
            if not plugin.should_execute(context):
                continue

            task = self._execute_single_plugin(plugin, hook_type, payload, context)
            tasks.append((plugin, task))

        results = []
        for plugin, task in tasks:
            result = await task
            results.append((plugin, result))

        return results

    async def _execute_single_plugin(self, plugin: BasePlugin, hook_type: HookType, payload: Any, context: PluginContext) -> PluginResult:
        """Execute a single plugin with error handling and stats"""
        start_time = asyncio.get_event_loop().time()
        stats_key = f"{plugin.name}:{hook_type.name}"

        try:
            # Check plugin health
            if not await plugin.health_check():
                logger.warning(f"Plugin {plugin.name} failed health check")
                return PluginResult(success=True)  # Don't block on unhealthy plugins

            # Execute plugin
            result = await asyncio.wait_for(plugin.execute(hook_type, payload, context), timeout=self.config.get("plugin_timeout", 30))

            # Update stats
            self._execution_stats[stats_key]["calls"] += 1
            self._execution_stats[stats_key]["total_time"] += asyncio.get_event_loop().time() - start_time

            return result

        except asyncio.TimeoutError:
            logger.error(f"Plugin {plugin.name} timed out for hook {hook_type.name}")
            self._execution_stats[stats_key]["errors"] += 1
            return PluginResult(success=False, error_message=f"Plugin {plugin.name} timed out")
        except Exception as e:
            logger.error(f"Plugin {plugin.name} error for hook {hook_type.name}: {e}")
            self._execution_stats[stats_key]["errors"] += 1
            return PluginResult(success=False, error_message=f"Plugin {plugin.name} error: {str(e)}")

    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        return dict(self._execution_stats)

    def reset_stats(self) -> None:
        """Reset execution statistics"""
        self._execution_stats.clear()

    async def reload_plugin(self, plugin_name: str) -> None:
        """Reload a specific plugin"""
        plugin = self.registry.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin {plugin_name} not found")

        # Shutdown old plugin
        await plugin.shutdown()
        self.registry.unregister(plugin_name)

        # Reload from config
        plugin_configs = self.config.get("plugins", [])
        for config in plugin_configs:
            if config.get("name") == plugin_name:
                await self.load_plugin(config)
                break
