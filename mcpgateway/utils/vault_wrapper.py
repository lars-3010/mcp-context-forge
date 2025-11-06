"""Vault secrets integration for MCP Gateway.

This module provides HashiCorp Vault integration for secure secrets management.
Supports both AppRole and Token-based authentication with automatic token renewal.
"""

import functools
import logging
import os
import time
from typing import Any, Optional

try:
    import hvac
    from hvac.exceptions import Forbidden, InvalidPath

    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False
    hvac = None  # type: ignore
    Forbidden = Exception  # type: ignore
    InvalidPath = Exception  # type: ignore

logger = logging.getLogger(__name__)

# Vault configuration from environment
MAX_RETRY = int(os.getenv("VAULT_MAX_RETRIES", "5"))
WAIT_TIME = int(os.getenv("VAULT_RETRY_INTERVAL", "5"))
TOKEN_RENEW_THRESHOLD = int(os.getenv("VAULT_TOKEN_RENEW_THRESHOLD_SECONDS", "60"))


def ensure_authenticated(func):  # type: ignore
    """Decorator to ensure Vault client is authenticated before executing operations.

    Automatically renews tokens when TTL is below threshold and re-authenticates
    if token is invalid or non-renewable.
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):  # type: ignore
        new_token = False
        try:
            token_details = self.client.auth.token.lookup_self()
            renewable = token_details["data"].get("renewable", False)
            token_ttl = token_details["data"]["ttl"]

            if not renewable:
                logger.debug("Token is not renewable")
                new_token = True
            elif token_ttl < TOKEN_RENEW_THRESHOLD:
                logger.debug(f"Token TTL ({token_ttl}s) below threshold, renewing")
                self.client.auth.token.renew_self()
        except Exception as exception:
            logger.debug(f"Token invalid, error: {str(exception)}")
            new_token = True

        if new_token:
            self.authenticate()

        return func(self, *args, **kwargs)

    return wrapper


class VaultAccess:
    """HashiCorp Vault client wrapper with authentication and secret management.

    Supports both AppRole and Token-based authentication with automatic token renewal
    and retry logic for resilience.

    Args:
        vault_url: Vault server URL (default: VAULT_URL env var)
        vault_token: Vault token for token-based auth (default: VAULT_TOKEN env var)
        client_id: AppRole role_id for AppRole auth (default: VAULT_CLIENT_ID env var)
        secret_id: AppRole secret_id for AppRole auth (default: VAULT_SECRET_ID env var)
        mount_point: AppRole mount point (default: derived from VAULT_SECRET_ENGINE)
        verify_ssl: Verify SSL certificates (default: VAULT_VERIFY_SSL env var)

    Examples:
        # Token-based authentication
        >>> vault = VaultAccess(vault_url="http://localhost:8200", vault_token="hvs.xxx")
        >>> secret = vault.get_secret("secret", "myapp/config")

        # AppRole authentication
        >>> vault = VaultAccess(
        ...     vault_url="http://localhost:8200",
        ...     client_id="role-id-xxx",
        ...     secret_id="secret-id-xxx"
        ... )
        >>> value = vault.get_value("secret", "myapp/db", "password")
    """

    def __init__(
        self,
        vault_url: Optional[str] = None,
        vault_token: Optional[str] = None,
        client_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        mount_point: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        """Initialize Vault client with authentication credentials."""
        if not HVAC_AVAILABLE:
            raise ImportError("hvac package is required for Vault integration. Install with: uv pip install hvac")

        self.vault_url = vault_url or os.getenv("VAULT_URL")

        # Read token from standard locations (in order of precedence):
        # 1. Explicit parameter
        # 2. VAULT_TOKEN env var (set by shell after unsealing)
        # 3. ~/.vault-token file (standard Vault CLI location)
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN") or self._read_token_file()

        self.client_id = client_id or os.getenv("VAULT_CLIENT_ID")
        self.secret_id = secret_id or os.getenv("VAULT_SECRET_ID")

        # Determine verify SSL setting
        if verify_ssl is None:
            verify_ssl_env = os.getenv("VAULT_VERIFY_SSL", "true").lower()
            verify_ssl = verify_ssl_env in ("true", "1", "yes")

        self.verify_ssl = verify_ssl

        # Determine mount point
        secret_engine = os.getenv("VAULT_SECRET_ENGINE", "secret")
        self.mount_point = mount_point or f"{secret_engine}_approle"

        # KV engine configuration
        self.kv_engine = os.getenv("VAULT_SECRET_ENGINE", "secret")
        self.default_path = os.getenv("VAULT_DEFAULT_PATH", "")

        if not self.vault_url:
            raise ValueError("VAULT_URL must be set in environment or provided to VaultAccess")

        # Initialize client
        self.client = hvac.Client(url=self.vault_url, verify=self.verify_ssl)
        self.authenticate()

    @staticmethod
    def _read_token_file() -> Optional[str]:
        """Read Vault token from standard ~/.vault-token file.

        This is the default location where Vault CLI stores tokens after authentication.

        Returns:
            str or None: Token content if file exists and is readable
        """
        token_file = os.path.expanduser("~/.vault-token")
        try:
            if os.path.exists(token_file):
                with open(token_file, "r") as f:
                    token = f.read().strip()
                    if token:
                        logger.debug(f"Read Vault token from {token_file}")
                        return token
        except Exception as e:
            logger.debug(f"Could not read token from {token_file}: {e}")
        return None

    def __call__(self) -> Any:
        """Return the hvac client instance."""
        if self.client is None:
            self.client = hvac.Client(url=self.vault_url, token=self.vault_token, verify=self.verify_ssl)
        return self.client

    def ping(self) -> bool:
        """Check if Vault client is authenticated.

        Returns:
            bool: True if authenticated, False otherwise
        """
        return self.client.is_authenticated()

    def authenticate(self) -> None:
        """Authenticate with Vault using AppRole or Token.

        Tries AppRole authentication if client_id and secret_id are provided,
        otherwise falls back to token-based authentication. Includes retry logic
        for transient failures.
        """
        retries = 0
        while retries < MAX_RETRY:
            try:
                if self.client_id and self.secret_id:
                    # AppRole authentication
                    logger.debug("Authenticating with Vault using AppRole")
                    self.client.auth.approle.login(role_id=self.client_id, secret_id=self.secret_id, mount_point=self.mount_point)
                    logger.info("Vault AppRole authentication successful")
                else:
                    # Token-based authentication
                    logger.debug("Authenticating with Vault using Token")
                    self.client.token = self.vault_token
                    self.client.auth.token.lookup_self()
                    logger.info("Vault Token authentication successful")
                return
            except Forbidden as exception:
                logger.error(f"Vault authentication forbidden - invalid token or role: {exception}")
                break
            except Exception as exception:
                retries += 1
                if retries >= MAX_RETRY:
                    logger.error(f"Exceeded maximum retries ({MAX_RETRY}) for Vault authentication: {exception}")
                    raise
                logger.warning(f"Vault authentication failed (attempt {retries}/{MAX_RETRY}), retrying in {WAIT_TIME}s: {exception}")
                time.sleep(WAIT_TIME)

    @ensure_authenticated
    def get_secret(self, kv_engine: str, secret_name: str) -> dict[str, Any]:
        """Retrieve all key-value pairs from a secret path.

        Args:
            kv_engine: KV secrets engine mount point
            secret_name: Path to the secret within the engine

        Returns:
            dict: Secret data as key-value pairs, empty dict on failure

        Examples:
            >>> vault = VaultAccess()
            >>> secret = vault.get_secret("secret", "mcpgateway/prod")
            >>> print(secret.get("jwt_secret_key"))
        """
        retries = 0
        while retries < MAX_RETRY:
            try:
                if not self.client.is_authenticated():
                    logger.error("Vault client is not authenticated")
                    return {}

                response = self.client.secrets.kv.v2.read_secret_version(path=secret_name, mount_point=kv_engine)
                secrets = response.get("data", {}).get("data", {})
                logger.debug(f"Retrieved secret from {kv_engine}/{secret_name}")
                return secrets
            except InvalidPath:
                logger.warning(f"Secret not found at {kv_engine}/{secret_name}")
                return {}
            except Exception as exception:
                retries += 1
                if retries >= MAX_RETRY:
                    logger.error(f"Failed to retrieve secret {kv_engine}/{secret_name}: {exception}")
                    return {}
                logger.debug(f"Retry {retries}/{MAX_RETRY} for get_secret due to: {exception}")
                time.sleep(WAIT_TIME)
        return {}

    @ensure_authenticated
    def get_value(self, kv_engine: str, secret_name: str, secret_key: str) -> Optional[str]:
        """Retrieve a specific key from a secret.

        Args:
            kv_engine: KV secrets engine mount point
            secret_name: Path to the secret within the engine
            secret_key: Specific key to retrieve from the secret

        Returns:
            str or None: Secret value, None if not found

        Examples:
            >>> vault = VaultAccess()
            >>> jwt_key = vault.get_value("secret", "mcpgateway/prod", "jwt_secret_key")
        """
        logger.debug(f"Getting secret value: {self.vault_url}/{kv_engine}/{secret_name}/{secret_key}")
        try:
            secret = self.get_secret(kv_engine, secret_name)
            return secret.get(secret_key)
        except Exception as exception:
            logger.error(f"Key '{secret_key}' not found in {kv_engine}/{secret_name}: {str(exception)}")
            return None

    @ensure_authenticated
    def kv_engine_path_exists(self, kv_engine: str, path: str) -> bool:
        """Check if a secret path exists in the KV engine.

        Args:
            kv_engine: KV secrets engine mount point
            path: Path to check within the engine

        Returns:
            bool: True if path exists, False otherwise
        """
        try:
            self.client.secrets.kv.v2.read_secret_version(path=path, mount_point=kv_engine)
            return True
        except Exception:
            return False

    @ensure_authenticated
    def create_secret(self, kv_engine: str, secret_path: str, secret_dict: dict[str, Any]) -> None:
        """Create or update a secret at the specified path.

        Args:
            kv_engine: KV secrets engine mount point
            secret_path: Path where to store the secret
            secret_dict: Dictionary of key-value pairs to store

        Examples:
            >>> vault = VaultAccess()
            >>> vault.create_secret("secret", "mcpgateway/dev", {
            ...     "jwt_secret_key": "my-secret-key",
            ...     "basic_auth_password": "changeme"
            ... })
        """
        try:
            if not self.client.is_authenticated():
                logger.error("Vault client is not authenticated")
                return

            self.client.secrets.kv.v2.create_or_update_secret(mount_point=kv_engine, path=secret_path, secret=secret_dict)
            logger.info(f"Successfully created/updated secret at {kv_engine}/{secret_path}")
        except InvalidPath as exception:
            logger.error(f"KV engine or path does not exist: {exception}")
        except Exception as exception:
            logger.error(f"Failed to create secret: {exception}")

    @ensure_authenticated
    def get_vault_token(self) -> Optional[str]:
        """Get the current Vault authentication token.

        Returns:
            str or None: Current token
        """
        return self.client.token


def load_secrets_from_vault(
    vault_path: Optional[str] = None, kv_engine: Optional[str] = None, prefix: str = "", update_env: bool = True
) -> dict[str, Any]:
    """Load secrets from Vault and optionally update environment variables.

    This function connects to Vault, retrieves secrets from the specified path,
    and can automatically populate environment variables with the retrieved values.

    Args:
        vault_path: Path to secrets in Vault (default: VAULT_SECRET_PATH env var)
        kv_engine: KV engine mount point (default: VAULT_SECRET_ENGINE env var)
        prefix: Optional prefix to add to environment variable names
        update_env: If True, update os.environ with retrieved secrets

    Returns:
        dict: Retrieved secrets as key-value pairs

    Examples:
        >>> # Load secrets and update environment
        >>> secrets = load_secrets_from_vault("mcpgateway/prod", "secret")
        >>> print(os.getenv("JWT_SECRET_KEY"))  # Now available

        >>> # Load without updating environment
        >>> secrets = load_secrets_from_vault(update_env=False)
        >>> jwt_key = secrets.get("JWT_SECRET_KEY")

    Raises:
        ImportError: If hvac package is not installed
    """
    if not HVAC_AVAILABLE:
        logger.warning("hvac package not available, skipping Vault secrets loading")
        return {}

    # Check if Vault is enabled
    vault_enabled = os.getenv("VAULT_ENABLED", "false").lower() in ("true", "1", "yes")
    if not vault_enabled:
        logger.debug("Vault integration is disabled (VAULT_ENABLED=false)")
        return {}

    try:
        # Initialize Vault client
        vault = VaultAccess()

        # Determine paths
        kv_engine = kv_engine or os.getenv("VAULT_SECRET_ENGINE", "secret")
        vault_path = vault_path or os.getenv("VAULT_SECRET_PATH")

        if not vault_path:
            logger.warning("VAULT_SECRET_PATH not configured, skipping Vault secrets loading")
            return {}

        # Retrieve secrets
        logger.info(f"Loading secrets from Vault: {kv_engine}/{vault_path}")
        secrets = vault.get_secret(kv_engine, vault_path)

        if not secrets:
            logger.warning(f"No secrets found at {kv_engine}/{vault_path}")
            return {}

        # Update environment variables if requested
        if update_env:
            for key, value in secrets.items():
                env_key = f"{prefix}{key}" if prefix else key
                os.environ[env_key] = str(value)
                logger.debug(f"Set environment variable: {env_key}")

            logger.info(f"Loaded {len(secrets)} secrets from Vault into environment")

        return secrets

    except Exception as exception:
        logger.error(f"Failed to load secrets from Vault: {exception}")
        return {}
