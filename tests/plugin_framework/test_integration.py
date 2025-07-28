#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration test for MCP Gateway Plugin Framework

Tests the plugin system with various scenarios.
"""

# Standard
import asyncio
from datetime import datetime
from unittest.mock import patch

# Third-Party
import pytest

# First-Party
from mcpgateway.plugin_framework import BasePlugin, HookType, PluginContext, PluginManager, PluginResult
from mcpgateway.plugins.example_plugins import LLMGuardPlugin, PIIFilterPlugin


class TestPluginFramework:
    """Test cases for the plugin framework"""

    @pytest.fixture
    async def plugin_manager(self):
        """Create a plugin manager for testing"""
        config = {"plugin_dirs": ["plugins/test"], "plugins": [], "parallel_execution_within_band": False, "plugin_timeout": 5}
        manager = PluginManager(config)
        await manager.initialize()
        yield manager
        await manager.shutdown()

    @pytest.fixture
    def plugin_context(self):
        """Create a test context"""
        return PluginContext(request_id="test-123", user="test@example.com", tenant_id="tenant-1", server_id="server-1", tool_name="test_tool")

    @pytest.mark.asyncio
    async def test_pii_filter_blocks_ssn(self, plugin_manager, plugin_context):
        """Test that PII filter detects and blocks SSN"""
        # Create and register PII filter
        pii_config = {"enabled": True, "mode": "enforcing", "block_on_pii": True}
        pii_filter = PIIFilterPlugin(pii_config)
        await pii_filter.initialize()
        plugin_manager.registry.register(pii_filter)

        # Test payload with SSN
        payload = {"tool_name": "customer_lookup", "arguments": {"query": "Find customer with SSN 123-45-6789"}}

        # Execute hook
        result = await plugin_manager.execute_hook(HookType.TOOL_PRE_INVOKE, payload, plugin_context)

        # Verify SSN was detected and blocked
        assert not result.success
        assert not result.continue_processing
        assert "PII_DETECTED" in result.error_code
        assert "ssn" in result.metadata["pii_types"]

    @pytest.mark.asyncio
    async def test_pii_filter_masks_data(self, plugin_manager, plugin_context):
        """Test that PII filter masks sensitive data when not blocking"""
        # Create PII filter that masks instead of blocks
        pii_config = {"enabled": True, "mode": "enforcing", "block_on_pii": False, "mask_character": "X"}
        pii_filter = PIIFilterPlugin(pii_config)
        await pii_filter.initialize()
        plugin_manager.registry.register(pii_filter)

        # Test payload with email
        payload = {"tool_name": "send_email", "arguments": {"to": "user@example.com", "message": "Contact me at john.doe@company.com"}}

        # Execute pre-hook
        result = await plugin_manager.execute_hook(HookType.TOOL_PRE_INVOKE, payload, plugin_context)

        # Verify email was masked
        assert result.success
        assert result.modified_payload
        args = result.modified_payload["arguments"]
        assert "XXXXXXXXXXXXXXXXXXXX" in args["message"]  # Masked email
        assert args["to"] == "XXXXXXXXXXXXXXXXXX"  # Masked email

    @pytest.mark.asyncio
    async def test_multiple_plugins_priority(self, plugin_manager, plugin_context):
        """Test that plugins execute in priority order"""
        execution_order = []

        # Create test plugins with different priorities
        class Plugin1(BasePlugin):
            name = "Plugin1"
            hooks = {HookType.TOOL_PRE_INVOKE}
            priority = 100

            async def execute(self, hook_type, payload, context):
                execution_order.append("Plugin1")
                return PluginResult(success=True)

        class Plugin2(BasePlugin):
            name = "Plugin2"
            hooks = {HookType.TOOL_PRE_INVOKE}
            priority = 50  # Higher priority (lower number)

            async def execute(self, hook_type, payload, context):
                execution_order.append("Plugin2")
                return PluginResult(success=True)

        class Plugin3(BasePlugin):
            name = "Plugin3"
            hooks = {HookType.TOOL_PRE_INVOKE}
            priority = 150

            async def execute(self, hook_type, payload, context):
                execution_order.append("Plugin3")
                return PluginResult(success=True)

        # Register plugins
        for plugin_class in [Plugin1, Plugin2, Plugin3]:
            plugin = plugin_class({})
            await plugin.initialize()
            plugin_manager.registry.register(plugin)

        # Execute hook
        await plugin_manager.execute_hook(HookType.TOOL_PRE_INVOKE, {"test": "data"}, plugin_context)

        # Verify execution order
        assert execution_order == ["Plugin2", "Plugin1", "Plugin3"]

    @pytest.mark.asyncio
    async def test_plugin_conditions(self, plugin_manager, plugin_context):
        """Test that plugins only execute when conditions match"""
        executed = []

        class ConditionalPlugin(BasePlugin):
            name = "ConditionalPlugin"
            hooks = {HookType.TOOL_PRE_INVOKE}

            async def execute(self, hook_type, payload, context):
                executed.append(self.name)
                return PluginResult(success=True)

        # Plugin that should execute (matches tool name)
        plugin1 = ConditionalPlugin({"conditions": {"tool_names": ["test_tool", "other_tool"]}})
        await plugin1.initialize()
        plugin_manager.registry.register(plugin1)

        # Plugin that should NOT execute (different tool)
        plugin2 = ConditionalPlugin({"conditions": {"tool_names": ["different_tool"]}})
        plugin2.name = "Plugin2"
        await plugin2.initialize()
        plugin_manager.registry.register(plugin2)

        # Execute hook
        await plugin_manager.execute_hook(HookType.TOOL_PRE_INVOKE, {}, plugin_context)

        # Verify only matching plugin executed
        assert executed == ["ConditionalPlugin"]

    @pytest.mark.asyncio
    async def test_permissive_mode(self, plugin_manager, plugin_context):
        """Test that permissive mode logs but doesn't block"""

        # Create a plugin that would block in enforcing mode
        class BlockingPlugin(BasePlugin):
            name = "BlockingPlugin"
            hooks = {HookType.TOOL_PRE_INVOKE}

            async def execute(self, hook_type, payload, context):
                return PluginResult(success=False, continue_processing=False, error_message="Would block this request")

        plugin = BlockingPlugin({"mode": "permissive"})  # Permissive mode
        await plugin.initialize()
        plugin_manager.registry.register(plugin)

        # Execute hook
        with patch("logging.Logger.warning") as mock_warning:
            result = await plugin_manager.execute_hook(HookType.TOOL_PRE_INVOKE, {}, plugin_context)

        # Verify request was NOT blocked
        assert result.success
        assert result.continue_processing

        # Verify warning was logged
        mock_warning.assert_called_once()
        assert "would block (permissive mode)" in mock_warning.call_args[0][0]

    @pytest.mark.asyncio
    async def test_external_service_timeout(self, plugin_manager, plugin_context):
        """Test that external service timeouts don't block requests"""
        # Mock LLMGuard plugin with timeout
        with patch("aiohttp.ClientSession") as mock_session:
            # Simulate timeout
            mock_session.return_value.__aenter__.return_value.post.side_effect = asyncio.TimeoutError

            llmguard = LLMGuardPlugin({"service_url": "http://test:8080", "timeout": 1, "mode": "enforcing"})
            await llmguard.initialize()
            plugin_manager.registry.register(llmguard)

            # Execute hook
            result = await plugin_manager.execute_hook(HookType.TOOL_PRE_INVOKE, {"arguments": {"text": "test"}}, plugin_context)

            # Verify timeout didn't block
            assert result.success
            assert "llmguard_timeout" in result.metadata

    @pytest.mark.asyncio
    async def test_state_sharing_between_hooks(self, plugin_manager, plugin_context):
        """Test that state is shared between pre and post hooks"""

        class StatefulPlugin(BasePlugin):
            name = "StatefulPlugin"
            hooks = {HookType.TOOL_PRE_INVOKE, HookType.TOOL_POST_INVOKE}

            async def execute(self, hook_type, payload, context):
                if hook_type == HookType.TOOL_PRE_INVOKE:
                    # Store state in pre-hook
                    context.set_state("test_value", "Hello from pre-hook")
                    context.set_state("timestamp", datetime.utcnow().isoformat())
                    return PluginResult(success=True)
                else:
                    # Retrieve state in post-hook
                    test_value = context.get_state("test_value")
                    timestamp = context.get_state("timestamp")
                    return PluginResult(success=True, metadata={"retrieved_value": test_value, "stored_at": timestamp})

        plugin = StatefulPlugin({})
        await plugin.initialize()
        plugin_manager.registry.register(plugin)

        # Execute pre-hook
        pre_result = await plugin_manager.execute_hook(HookType.TOOL_PRE_INVOKE, {}, plugin_context)

        # Execute post-hook with same context
        post_result = await plugin_manager.execute_hook(HookType.TOOL_POST_INVOKE, {}, plugin_context)

        # Verify state was preserved
        assert post_result.metadata["retrieved_value"] == "Hello from pre-hook"
        assert "stored_at" in post_result.metadata


# Example of running a simple test
async def main():
    """Run a simple test of the plugin framework"""

    # Create plugin manager
    manager = PluginManager(
        {
            "plugin_dirs": ["plugins/"],
            "plugins": [
                {
                    "name": "TestPIIFilter",
                    "type": "module",
                    "module_path": "mcpgateway.plugins.example_plugins",
                    "class_name": "PIIFilterPlugin",
                    "enabled": True,
                    "mode": "enforcing",
                    "config": {"block_on_pii": False, "mask_character": "*"},
                }
            ],
        }
    )

    await manager.initialize()

    # Create test context
    context = PluginContext(request_id="demo-123", user="demo@example.com", tool_name="customer_service")

    # Test with PII
    print("Testing PII detection and masking...")
    payload = {"tool_name": "customer_service", "arguments": {"customer_email": "john.doe@example.com", "notes": "Customer SSN is 123-45-6789, phone: 555-123-4567"}}

    result = await manager.execute_hook(HookType.TOOL_PRE_INVOKE, payload, context)

    if result.modified_payload:
        print(f"Original: {payload['arguments']}")
        print(f"Masked: {result.modified_payload['arguments']}")
        print(f"Metadata: {result.metadata}")

    # Get stats
    stats = manager.get_stats()
    print(f"\nPlugin execution stats: {stats}")

    await manager.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
