# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/utils/gateway_cookie_store.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Gateway Cookie Store for Session Persistence.

This module provides cookie storage and retrieval for MCP gateways that use
session-based authentication. Cookies are stored in Redis with gateway_id as
the key, enabling authentication persistence across multiple tool invocations.

Use case:
    Some MCP servers require browser-based authentication and maintain sessions
    via HTTP cookies. Without persistence, each tool invocation creates a new
    session, forcing users to re-authenticate every time.

Security note:
    Cookies are stored at the gateway level (not per-user). Only enable cookie
    persistence in trusted environments where all users should share the same
    authentication session with the upstream MCP server.

Examples:
    >>> from mcpgateway.utils.gateway_cookie_store import GatewayCookieStore
    >>> import asyncio
    >>> store = GatewayCookieStore()
    >>> # Save cookies after authentication
    >>> cookies = {"sessionid": "abc123", "csrf_token": "xyz789"}
    >>> asyncio.run(store.save_cookies("gateway-id-123", cookies))
    >>> # Load cookies for subsequent requests
    >>> loaded = asyncio.run(store.load_cookies("gateway-id-123"))
    >>> loaded.get("sessionid")
    'abc123'
    >>> # Delete cookies
    >>> asyncio.run(store.delete_cookies("gateway-id-123"))
"""

# Standard
import json
import logging
from typing import Dict, Optional

# First-Party
from mcpgateway.config import settings
from mcpgateway.services.logging_service import LoggingService

# Initialize logging
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

# Check Redis availability
try:
    # Third-Party
    from redis.asyncio import Redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available - gateway cookie persistence will be disabled")


class GatewayCookieStore:
    """Store and retrieve cookies for gateway sessions using Redis.

    This class manages HTTP cookies for MCP gateways that use session-based
    authentication. Cookies are stored in Redis with a TTL matching SESSION_TTL
    to automatically expire unused sessions.

    Key features:
        - Gateway-level cookie storage (shared across users)
        - Automatic TTL expiration
        - Graceful fallback when Redis unavailable
        - Thread-safe operations via Redis

    Examples:
        >>> store = GatewayCookieStore()
        >>> import asyncio
        >>> cookies = {"session": "abc", "token": "xyz"}
        >>> asyncio.run(store.save_cookies("gw1", cookies))
        >>> loaded = asyncio.run(store.load_cookies("gw1"))
        >>> loaded["session"]
        'abc'
    """

    def __init__(self):
        """Initialize the cookie store with Redis connection if available."""
        self._redis: Optional[Redis] = None
        self._redis_available = REDIS_AVAILABLE and settings.cache_type == "redis"

        if self._redis_available:
            try:
                self._redis = Redis.from_url(
                    settings.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                )
                logger.debug("Gateway cookie store initialized with Redis backend")
            except Exception as e:
                logger.warning(f"Failed to initialize Redis for cookie store: {e}")
                self._redis_available = False
        else:
            if not REDIS_AVAILABLE:
                logger.debug("Redis library not available - cookie persistence disabled")
            elif settings.cache_type != "redis":
                logger.debug(f"Cache type is '{settings.cache_type}' (not redis) - cookie persistence disabled")

    def _get_redis_key(self, gateway_id: str) -> str:
        """Generate Redis key for gateway cookies.

        Args:
            gateway_id: The gateway identifier

        Returns:
            Redis key string in format "gateway_cookies:{gateway_id}"

        Examples:
            >>> store = GatewayCookieStore()
            >>> store._get_redis_key("abc-123")
            'gateway_cookies:abc-123'
        """
        return f"gateway_cookies:{gateway_id}"

    async def save_cookies(self, gateway_id: str, cookies: Dict[str, str]) -> bool:
        """Save cookies for a gateway to Redis.

        Stores cookies as JSON with TTL matching SESSION_TTL configuration.
        If Redis is unavailable, logs a warning and returns False.

        Args:
            gateway_id: The gateway identifier
            cookies: Dictionary of cookie name-value pairs

        Returns:
            True if cookies were saved successfully, False otherwise

        Examples:
            >>> store = GatewayCookieStore()
            >>> import asyncio
            >>> cookies = {"session_id": "abc123", "auth_token": "xyz"}
            >>> asyncio.run(store.save_cookies("gw-001", cookies))
            True
        """
        if not self._redis_available or not self._redis:
            logger.debug("Redis not available - skipping cookie save")
            return False

        if not cookies:
            logger.debug(f"No cookies to save for gateway {gateway_id}")
            return True

        try:
            redis_key = self._get_redis_key(gateway_id)
            cookies_json = json.dumps(cookies)
            ttl = settings.session_ttl  # Match session TTL

            await self._redis.setex(redis_key, ttl, cookies_json)
            logger.debug(f"Saved {len(cookies)} cookies for gateway {gateway_id} (TTL: {ttl}s)")
            return True

        except Exception as e:
            logger.error(f"Failed to save cookies for gateway {gateway_id}: {e}")
            return False

    async def load_cookies(self, gateway_id: str) -> Dict[str, str]:
        """Load cookies for a gateway from Redis.

        Retrieves stored cookies if available. Returns empty dict if not found
        or if Redis is unavailable.

        Args:
            gateway_id: The gateway identifier

        Returns:
            Dictionary of cookie name-value pairs (empty if not found)

        Examples:
            >>> store = GatewayCookieStore()
            >>> import asyncio
            >>> # Assuming cookies were previously saved
            >>> cookies = asyncio.run(store.load_cookies("gw-001"))
            >>> isinstance(cookies, dict)
            True
        """
        if not self._redis_available or not self._redis:
            logger.debug("Redis not available - returning empty cookies")
            return {}

        try:
            redis_key = self._get_redis_key(gateway_id)
            cookies_json = await self._redis.get(redis_key)

            if not cookies_json:
                logger.debug(f"No cookies found for gateway {gateway_id}")
                return {}

            cookies = json.loads(cookies_json)
            logger.debug(f"Loaded {len(cookies)} cookies for gateway {gateway_id}")
            return cookies

        except Exception as e:
            logger.error(f"Failed to load cookies for gateway {gateway_id}: {e}")
            return {}

    async def delete_cookies(self, gateway_id: str) -> bool:
        """Delete cookies for a gateway from Redis.

        Removes stored cookies. Useful for logout or session invalidation.

        Args:
            gateway_id: The gateway identifier

        Returns:
            True if cookies were deleted or didn't exist, False on error

        Examples:
            >>> store = GatewayCookieStore()
            >>> import asyncio
            >>> asyncio.run(store.delete_cookies("gw-001"))
            True
        """
        if not self._redis_available or not self._redis:
            logger.debug("Redis not available - skipping cookie delete")
            return False

        try:
            redis_key = self._get_redis_key(gateway_id)
            deleted = await self._redis.delete(redis_key)
            logger.debug(f"Deleted cookies for gateway {gateway_id} (existed: {deleted > 0})")
            return True

        except Exception as e:
            logger.error(f"Failed to delete cookies for gateway {gateway_id}: {e}")
            return False

    async def close(self):
        """Close Redis connection.

        Call this during application shutdown to properly clean up resources.

        Examples:
            >>> store = GatewayCookieStore()
            >>> import asyncio
            >>> asyncio.run(store.close())
        """
        if self._redis:
            try:
                await self._redis.aclose()
                logger.debug("Gateway cookie store closed")
            except Exception as e:
                logger.error(f"Error closing Redis connection: {e}")


# Global instance for reuse
_cookie_store: Optional[GatewayCookieStore] = None


def get_cookie_store() -> GatewayCookieStore:
    """Get or create the global cookie store instance.

    Returns:
        The global GatewayCookieStore instance

    Examples:
        >>> store1 = get_cookie_store()
        >>> store2 = get_cookie_store()
        >>> store1 is store2
        True
    """
    global _cookie_store
    if _cookie_store is None:
        _cookie_store = GatewayCookieStore()
    return _cookie_store
