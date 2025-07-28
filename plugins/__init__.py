# plugins/__init__.py
"""
MCP Gateway Plugins Package
"""

# plugins/native/__init__.py
"""
Native plugins that run in-process with MCP Gateway.
"""

# plugins/native/pii_filter/__init__.py
"""
PII Filter Plugin for MCP Gateway
"""
from .plugin import PIIFilterPlugin

__all__ = ['PIIFilterPlugin']

# plugins/microservices/__init__.py
"""
Microservice plugins that integrate with external services.
"""

# plugins/microservices/llmguard/__init__.py
"""
LLMGuard Plugin for MCP Gateway
"""
from .plugin import LLMGuardPlugin

__all__ = ['LLMGuardPlugin']
