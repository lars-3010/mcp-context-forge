# -*- coding: utf-8 -*-
"""
Example passthrough plugin for MCP Gateway.
Implements passthrough hooks: on_passthrough_request and on_passthrough_response.
"""

from typing import Any, Dict

class ExamplePassthroughPlugin:
    """
    Example passthrough plugin implementing pre/post passthrough hooks.
    Register this plugin in your config to activate passthrough plugin chains.
    """
    name = "example_passthrough"
    version = "0.1.0"
    description = "Example plugin for passthrough pre/post hooks."

    async def on_passthrough_request(self, context: Dict[str, Any], request: Any) -> None:
        """
        Pre-passthrough hook. Mutate context or request as needed.
        """
        print(f"[PassthroughPlugin] Pre-hook: {self.name} for tool {context.get('tool')}")
        # Example: Add a custom header
        if hasattr(request, 'headers'):
            request.headers['X-Example-Pre'] = 'set-by-plugin'
        # Example: Add a log entry to context
        context['passthrough_pre'] = True

    async def on_passthrough_response(self, context: Dict[str, Any], request: Any, response: Any) -> None:
        """
        Post-passthrough hook. Mutate context or response as needed.
        """
        print(f"[PassthroughPlugin] Post-hook: {self.name} for tool {context.get('tool')}")
        # Example: Add a custom header to response if possible
        if hasattr(response, 'headers'):
            response.headers['X-Example-Post'] = 'set-by-plugin'
        # Example: Add a log entry to context
        context['passthrough_post'] = True
