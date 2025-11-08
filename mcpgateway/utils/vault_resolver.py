"""Vault reference resolver for dynamic credential injection.

This module provides utilities for resolving Vault references in configuration values.
It supports the format: vault:kv_engine/path:key

Examples:
    vault:secret/confluence/mcp-server:email
    vault:secret/confluence/mcp-server:api_token
"""

import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from mcpgateway.services.logging_service import LoggingService

# Initialize logging
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

# Vault reference pattern: vault:engine/path:key
VAULT_REF_PATTERN = re.compile(r"^vault:([^/]+)/([^:]+):(.+)$")

# Credential cache: {vault_ref: (value, expiry_timestamp)}
_credential_cache: Dict[str, Tuple[str, float]] = {}

# Cache TTL in seconds (default: 5 minutes)
VAULT_CACHE_TTL = int(os.getenv("VAULT_CACHE_TTL_SECONDS", "300"))


def is_vault_reference(value: str) -> bool:
    """Check if a string is a vault reference.

    Args:
        value: String to check

    Returns:
        bool: True if value matches vault reference pattern

    Examples:
        >>> is_vault_reference("vault:secret/app/config:password")
        True
        >>> is_vault_reference("regular_value")
        False
        >>> is_vault_reference("")
        False
    """
    if not isinstance(value, str) or not value:
        return False
    return VAULT_REF_PATTERN.match(value) is not None


def parse_vault_reference(vault_ref: str) -> Optional[Dict[str, str]]:
    """Parse a vault reference string into components.

    Args:
        vault_ref: Vault reference string (e.g., "vault:secret/app/config:password")

    Returns:
        Dict with keys: kv_engine, secret_path, secret_key
        None if format is invalid

    Examples:
        >>> result = parse_vault_reference("vault:secret/confluence/mcp:email")
        >>> result == {"kv_engine": "secret", "secret_path": "confluence/mcp", "secret_key": "email"}
        True
    """
    match = VAULT_REF_PATTERN.match(vault_ref)
    if not match:
        logger.warning(f"Invalid vault reference format: {vault_ref}")
        return None

    kv_engine, secret_path, secret_key = match.groups()
    return {"kv_engine": kv_engine, "secret_path": secret_path, "secret_key": secret_key}


def resolve_vault_reference(vault_ref: str, use_cache: bool = True) -> Optional[str]:
    """Resolve a vault reference to its actual value with optional caching.

    Args:
        vault_ref: Vault reference string
        use_cache: Whether to use cached values (default: True)

    Returns:
        The resolved secret value, or None if resolution fails

    Examples:
        >>> # Assuming vault has secret/test/config with key=value: "test_value"
        >>> resolve_vault_reference("vault:secret/test/config:key")  # doctest: +SKIP
        'test_value'
    """
    # Check if vault is enabled
    vault_enabled = os.getenv("VAULT_ENABLED", "false").lower() in ("true", "1", "yes")
    if not vault_enabled:
        logger.warning(f"Vault is disabled but vault reference found: {vault_ref}")
        return None

    # Check cache first (if enabled)
    if use_cache and vault_ref in _credential_cache:
        cached_value, expiry = _credential_cache[vault_ref]
        if time.time() < expiry:
            logger.debug(f"Using cached vault credential: {vault_ref}")
            return cached_value
        else:
            logger.debug(f"Vault cache expired for: {vault_ref}")
            del _credential_cache[vault_ref]

    # Parse the reference
    parsed = parse_vault_reference(vault_ref)
    if not parsed:
        return None

    try:
        # Import vault wrapper (may not be available)
        from mcpgateway.utils.vault_wrapper import VaultAccess  # pylint: disable=import-outside-toplevel

        # Initialize vault client
        vault = VaultAccess()

        # Retrieve the secret value
        value = vault.get_value(kv_engine=parsed["kv_engine"], secret_name=parsed["secret_path"], secret_key=parsed["secret_key"])

        if value:
            logger.debug(f"Resolved vault reference: {parsed['kv_engine']}/{parsed['secret_path']}:{parsed['secret_key']}")

            # Cache the value
            if use_cache:
                _credential_cache[vault_ref] = (value, time.time() + VAULT_CACHE_TTL)
                logger.debug(f"Cached vault credential for {VAULT_CACHE_TTL}s: {vault_ref}")

            return value
        else:
            logger.warning(f"No value found for vault reference: {vault_ref}")
            return None

    except ImportError:
        logger.error("Vault integration not available (hvac package not installed)")
        return None
    except Exception as e:
        logger.error(f"Failed to resolve vault reference '{vault_ref}': {e}")
        return None


def clear_vault_cache() -> None:
    """Clear all cached vault credentials.

    Useful for forcing credential refresh or during testing.
    """
    global _credential_cache
    _credential_cache.clear()
    logger.info("Cleared vault credential cache")


def resolve_vault_in_dict(data: Dict[str, Any], recursive: bool = True) -> Dict[str, Any]:
    """Resolve all vault references in a dictionary.

    Args:
        data: Dictionary that may contain vault references
        recursive: If True, recursively resolve nested dictionaries

    Returns:
        Dictionary with vault references replaced by actual values

    Examples:
        >>> data = {"key": "vault:secret/app:password", "other": "value"}
        >>> resolved = resolve_vault_in_dict(data)  # doctest: +SKIP
        >>> # resolved["key"] will contain the actual password from vault
    """
    resolved = {}
    for key, value in data.items():
        if isinstance(value, str) and is_vault_reference(value):
            # Resolve the vault reference
            resolved_value = resolve_vault_reference(value)
            resolved[key] = resolved_value if resolved_value is not None else value
        elif isinstance(value, dict) and recursive:
            # Recursively resolve nested dictionaries
            resolved[key] = resolve_vault_in_dict(value, recursive=True)
        elif isinstance(value, list) and recursive:
            # Resolve vault references in lists
            resolved[key] = [resolve_vault_in_dict(item, recursive=True) if isinstance(item, dict) else resolve_vault_reference(item) if isinstance(item, str) and is_vault_reference(item) else item for item in value]
        else:
            resolved[key] = value

    return resolved


def resolve_vault_in_auth_headers(auth_headers: Optional[List[Dict[str, str]]]) -> Optional[List[Dict[str, str]]]:
    """Resolve vault references in gateway auth_headers.

    Args:
        auth_headers: List of header dicts with 'key' and 'value' fields

    Returns:
        List of headers with vault references resolved

    Examples:
        >>> headers = [
        ...     {"key": "x-api-token", "value": "vault:secret/api:token"},
        ...     {"key": "x-user", "value": "regular_value"}
        ... ]
        >>> resolved = resolve_vault_in_auth_headers(headers)  # doctest: +SKIP
    """
    if not auth_headers:
        return auth_headers

    resolved_headers = []
    for header in auth_headers:
        if not isinstance(header, dict) or "key" not in header or "value" not in header:
            resolved_headers.append(header)
            continue

        value = header["value"]
        if isinstance(value, str) and is_vault_reference(value):
            resolved_value = resolve_vault_reference(value)
            if resolved_value is not None:
                resolved_headers.append({"key": header["key"], "value": resolved_value})
                logger.info(f"Resolved vault reference for header: {header['key']}")
            else:
                logger.warning(f"Failed to resolve vault reference for header '{header['key']}': {value}")
                resolved_headers.append(header)  # Keep original if resolution fails
        else:
            resolved_headers.append(header)

    return resolved_headers
