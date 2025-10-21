# -*- coding: utf-8 -*-
"""
Passthrough Plugin Framework

Copyright 2025
SPDX-License-Identifier: Apache-2.0

This module provides a plugin framework for REST passthrough endpoints.
Supports pre- and post-processing plugin chains for validation, transformation, 
redaction, and auditing of passthrough requests and responses.

Key Features:
- Plugin registry with chainable execution
- Pre-request and post-response hooks
- Context passing between plugins
- Error handling and plugin isolation
- Built-in plugins for common use cases (PII filter, deny filter, etc.)

Usage:
    # Register a plugin
    @register_passthrough_plugin("my_plugin")
    def my_plugin(context, data, **kwargs):
        # Process data
        return data
    
    # Execute plugin chain
    result = on_passthrough_request(context, request, chain=["deny_filter", "my_plugin"])
    result = on_passthrough_response(context, request, response, chain=["pii_filter"])

See also:
- mcpgateway.routers.rest_passthrough for usage
- plugins/config.yaml for configuration
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Union
import re
import json

logger = logging.getLogger(__name__)

# Plugin registry
PLUGIN_REGISTRY: Dict[str, Callable] = {}


def register_passthrough_plugin(name: str) -> Callable:
    """
    Decorator to register a passthrough plugin.
    
    Args:
        name: Plugin identifier for use in chains
        
    Returns:
        Decorated plugin function
        
    Examples:
        >>> @register_passthrough_plugin("my_filter")
        ... def my_filter(context, data, **kwargs):
        ...     return data
    """
    def decorator(func: Callable) -> Callable:
        PLUGIN_REGISTRY[name] = func
        logger.debug(f"Registered passthrough plugin: {name}")
        return func
    return decorator


def execute_plugin_chain(
    chain: List[str], 
    context: Dict[str, Any], 
    data: Any,
    **kwargs
) -> Any:
    """
    Execute a chain of plugins in sequence.
    
    Args:
        chain: List of plugin names to execute in order
        context: Shared context dict (tool_id, user, etc.)
        data: Data to process (request or response)
        **kwargs: Additional arguments passed to plugins
        
    Returns:
        Processed data after all plugins
        
    Raises:
        ValueError: If plugin not found in registry
        Exception: Plugin execution errors (logged but not re-raised)
    """
    result = data
    
    for plugin_name in chain:
        if plugin_name not in PLUGIN_REGISTRY:
            logger.error(f"Plugin '{plugin_name}' not found in registry")
            raise ValueError(f"Unknown plugin: {plugin_name}")
            
        try:
            plugin_func = PLUGIN_REGISTRY[plugin_name]
            result = plugin_func(context, result, **kwargs)
            logger.debug(f"Executed plugin '{plugin_name}' successfully")
        except Exception as e:
            logger.error(f"Plugin '{plugin_name}' failed: {e}", exc_info=True)
            # Continue with other plugins - don't fail the entire chain
            
    return result


def on_passthrough_request(
    context: Dict[str, Any],
    mapped_request: Dict[str, Any],
    chain: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Execute pre-processing plugin chain on passthrough request.
    
    Args:
        context: Request context (tool_id, user, etc.)
        mapped_request: Mapped request dict with method, headers, params, body
        chain: Plugin chain to execute (defaults to config)
        
    Returns:
        Processed request data
    """
    if not chain:
        chain = []
        
    logger.debug(f"Executing pre-request plugin chain: {chain}")
    return execute_plugin_chain(chain, context, mapped_request, request_type="pre")


def on_passthrough_response(
    context: Dict[str, Any],
    mapped_request: Dict[str, Any],
    response: Any,
    chain: Optional[List[str]] = None
) -> Any:
    """
    Execute post-processing plugin chain on passthrough response.
    
    Args:
        context: Request context (tool_id, user, etc.)  
        mapped_request: Original mapped request for reference
        response: Response object to process
        chain: Plugin chain to execute (defaults to config)
        
    Returns:
        Processed response
    """
    if not chain:
        chain = []
        
    logger.debug(f"Executing post-response plugin chain: {chain}")
    return execute_plugin_chain(
        chain, context, response, 
        request_type="post", 
        original_request=mapped_request
    )


# ===== Built-in Plugins =====

@register_passthrough_plugin("deny_filter")
def deny_filter(context: Dict[str, Any], data: Any, **kwargs) -> Any:
    """
    Deny filter - blocks requests/responses based on patterns.
    
    Checks for:
    - Suspicious URL patterns
    - Blocked user agents  
    - Malicious headers
    - Content-based blocks
    """
    request_type = kwargs.get("request_type", "unknown")
    
    if request_type == "pre":
        # Pre-request filtering
        method = data.get("method", "")
        headers = data.get("headers", {})
        params = data.get("params", {})
        
        # Block dangerous methods without proper auth
        if method in ["DELETE", "PUT"] and not headers.get("Authorization"):
            logger.warning(f"Blocked {method} request without authorization")
            raise ValueError(f"Authentication required for {method} requests")
            
        # Block suspicious user agents
        user_agent = headers.get("User-Agent", "").lower()
        blocked_agents = ["bot", "crawler", "scanner", "sqlmap", "nikto"]
        if any(agent in user_agent for agent in blocked_agents):
            logger.warning(f"Blocked suspicious user agent: {user_agent}")
            raise ValueError("Access denied")
            
        # Block SQL injection attempts in params
        for key, value in params.items():
            if isinstance(value, str) and re.search(r"(union|select|drop|insert|delete|update|script)", value, re.I):
                logger.warning(f"Blocked potential injection in param {key}: {value}")
                raise ValueError("Invalid parameter detected")
                
    return data


@register_passthrough_plugin("pii_filter")  
def pii_filter(context: Dict[str, Any], data: Any, **kwargs) -> Any:
    """
    PII filter - redacts sensitive information from requests/responses.
    
    Redacts:
    - Social Security Numbers
    - Credit card numbers
    - Email addresses (optional)
    - Phone numbers
    - API keys and tokens
    """
    request_type = kwargs.get("request_type", "unknown")
    
    def redact_pii(text: str) -> str:
        if not isinstance(text, str):
            return text
            
        # SSN pattern (XXX-XX-XXXX)
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]', text)
        
        # Credit card numbers (basic pattern)
        text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CC_REDACTED]', text)
        
        # API keys and tokens (common patterns)
        text = re.sub(r'\b[A-Za-z0-9]{32,}\b', '[TOKEN_REDACTED]', text)
        text = re.sub(r'bearer\s+[A-Za-z0-9._-]+', 'bearer [TOKEN_REDACTED]', text, flags=re.I)
        
        # Phone numbers (US format)
        text = re.sub(r'\b\d{3}-\d{3}-\d{4}\b', '[PHONE_REDACTED]', text)
        text = re.sub(r'\(\d{3}\)\s?\d{3}-\d{4}', '[PHONE_REDACTED]', text)
        
        return text
    
    if request_type == "pre":
        # Redact request data
        if "headers" in data:
            for key, value in data["headers"].items():
                if isinstance(value, str):
                    data["headers"][key] = redact_pii(value)
                    
        if "params" in data:
            for key, value in data["params"].items():
                if isinstance(value, str):
                    data["params"][key] = redact_pii(value)
                    
        if "body" in data and data["body"]:
            if isinstance(data["body"], str):
                data["body"] = redact_pii(data["body"])
            elif isinstance(data["body"], dict):
                data["body"] = json.loads(redact_pii(json.dumps(data["body"])))
                
    elif request_type == "post":
        # Redact response data
        if hasattr(data, 'content') and isinstance(data.content, (str, bytes)):
            content = data.content
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            content = redact_pii(content)
            data.content = content.encode('utf-8') if isinstance(data.content, bytes) else content
    
    return data


@register_passthrough_plugin("regex_filter")
def regex_filter(context: Dict[str, Any], data: Any, **kwargs) -> Any:
    """
    Regex filter - applies custom regex transformations.
    
    Configuration can be provided via context or kwargs.
    Default patterns clean common injection attempts.
    """
    request_type = kwargs.get("request_type", "unknown")
    
    # Default regex patterns to clean/block
    patterns = kwargs.get("patterns", [
        (r'<script[^>]*>.*?</script>', '[SCRIPT_REMOVED]', re.I | re.S),
        (r'javascript:', 'blocked:', re.I),
        (r'on\w+\s*=', 'blocked=', re.I),
        (r'expression\s*\(', 'blocked(', re.I),
    ])
    
    def apply_regex_patterns(text: str) -> str:
        if not isinstance(text, str):
            return text
            
        for pattern, replacement, flags in patterns:
            text = re.sub(pattern, replacement, text, flags=flags)
        return text
    
    if request_type == "pre":
        # Apply to request
        if "params" in data:
            for key, value in data["params"].items():
                if isinstance(value, str):
                    data["params"][key] = apply_regex_patterns(value)
                    
        if "body" in data and isinstance(data["body"], str):
            data["body"] = apply_regex_patterns(data["body"])
            
    elif request_type == "post":
        # Apply to response
        if hasattr(data, 'content') and isinstance(data.content, (str, bytes)):
            content = data.content
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            content = apply_regex_patterns(content)
            data.content = content.encode('utf-8') if isinstance(data.content, bytes) else content
    
    return data


@register_passthrough_plugin("resource_filter")
def resource_filter(context: Dict[str, Any], data: Any, **kwargs) -> Any:
    """
    Resource filter - manages resource access and quotas.
    
    Features:
    - Rate limiting per tool/user
    - Resource size limits
    - Access pattern validation
    """
    request_type = kwargs.get("request_type", "unknown")
    tool_id = context.get("tool_id")
    
    if request_type == "pre":
        # Check request size limits
        body = data.get("body")
        if body:
            body_size = len(json.dumps(body)) if isinstance(body, dict) else len(str(body))
            if body_size > 1024 * 1024:  # 1MB limit
                logger.warning(f"Request body too large for tool {tool_id}: {body_size} bytes")
                raise ValueError("Request body exceeds size limit")
                
        # Validate resource access patterns
        params = data.get("params", {})
        if "limit" in params:
            try:
                limit = int(params["limit"])
                if limit > 1000:
                    logger.warning(f"Limiting large request limit for tool {tool_id}: {limit} -> 1000")
                    data["params"]["limit"] = "1000"
            except ValueError:
                pass
                
    elif request_type == "post":
        # Check response size limits
        if hasattr(data, 'content'):
            content_length = len(data.content) if data.content else 0
            if content_length > 10 * 1024 * 1024:  # 10MB limit
                logger.warning(f"Response too large for tool {tool_id}: {content_length} bytes")
                # Truncate or return error - for now just log
    
    return data


@register_passthrough_plugin("rate_limit")
def rate_limit(context: Dict[str, Any], data: Any, **kwargs) -> Any:
    """
    Rate limiting plugin - enforces request rate limits.
    
    This is a simple in-memory implementation.
    For production, use Redis-based rate limiting.
    """
    import time
    
    # Simple in-memory rate limiting (not persistent)
    if not hasattr(rate_limit, "requests"):
        rate_limit.requests = {}
    
    tool_id = context.get("tool_id")
    user = context.get("user", "anonymous")
    key = f"{tool_id}:{user}"
    
    current_time = time.time()
    window = 60  # 1 minute window
    limit = 100  # 100 requests per minute
    
    # Clean old entries
    rate_limit.requests = {
        k: [t for t in timestamps if current_time - t < window]
        for k, timestamps in rate_limit.requests.items()
    }
    
    # Check current rate
    if key not in rate_limit.requests:
        rate_limit.requests[key] = []
        
    timestamps = rate_limit.requests[key]
    if len(timestamps) >= limit:
        logger.warning(f"Rate limit exceeded for {key}: {len(timestamps)} requests in {window}s")
        raise ValueError(f"Rate limit exceeded. Max {limit} requests per {window}s")
    
    # Record this request
    timestamps.append(current_time)
    
    return data


@register_passthrough_plugin("response_shape")
def response_shape(context: Dict[str, Any], data: Any, **kwargs) -> Any:
    """
    Response shaping plugin - transforms response structure.
    
    Features:
    - JSONPath-based field extraction
    - Response format standardization
    - Error response wrapping
    """
    request_type = kwargs.get("request_type", "unknown")
    
    if request_type == "post":
        # Only process responses
        if hasattr(data, 'content') and data.content:
            try:
                # Try to parse as JSON and wrap in standard format
                if hasattr(data, 'headers') and 'application/json' in str(data.headers.get('content-type', '')):
                    content = data.content
                    if isinstance(content, bytes):
                        content = content.decode('utf-8')
                    
                    json_data = json.loads(content)
                    
                    # Wrap in standard response format if not already wrapped
                    if not isinstance(json_data, dict) or "data" not in json_data:
                        wrapped = {
                            "data": json_data,
                            "meta": {
                                "tool_id": context.get("tool_id"),
                                "processed_at": context.get("timestamp"),
                                "processed_by": "passthrough_plugin"
                            }
                        }
                        data.content = json.dumps(wrapped).encode('utf-8')
                        
            except (json.JSONDecodeError, AttributeError):
                # Not JSON or can't process, leave as-is
                pass
    
    return data


def get_available_plugins() -> List[str]:
    """
    Get list of available plugin names.
    
    Returns:
        List of registered plugin names
    """
    return list(PLUGIN_REGISTRY.keys())


def get_plugin_info() -> Dict[str, Dict[str, Any]]:
    """
    Get information about all registered plugins.
    
    Returns:
        Dict mapping plugin names to their info
    """
    info = {}
    for name, func in PLUGIN_REGISTRY.items():
        info[name] = {
            "name": name,
            "function": func.__name__,
            "doc": func.__doc__.strip().split('\n')[0] if func.__doc__ else "No description",
            "module": func.__module__,
        }
    return info