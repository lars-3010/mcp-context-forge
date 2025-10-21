# -*- coding: utf-8 -*-
"""
Passthrough Configuration Helper

Copyright 2025
SPDX-License-Identifier: Apache-2.0

This module provides configuration loading and validation for REST passthrough functionality.
It reads configuration from plugins/config.yaml and provides defaults for passthrough settings.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml

from mcpgateway.config import settings

logger = logging.getLogger(__name__)


class PassthroughConfig:
    """Configuration manager for REST passthrough functionality."""
    
    def __init__(self):
        """Initialize passthrough configuration."""
        self._config = None
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from plugins/config.yaml."""
        try:
            # Try to get plugin config file path from settings, fallback to default
            try:
                config_path = Path(settings.plugin_config_file)
            except (ImportError, AttributeError):
                config_path = Path("plugins/config.yaml")
                
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    full_config = yaml.safe_load(f)
                    self._config = full_config.get('passthrough', {})
                    logger.debug(f"Loaded passthrough config from {config_path}")
            else:
                logger.warning(f"Plugin config file not found: {config_path}")
                self._config = {}
        except Exception as e:
            logger.error(f"Failed to load passthrough config: {e}")
            self._config = {}
        
        # Apply defaults if not set
        self._apply_defaults()
    
    def _apply_defaults(self) -> None:
        """Apply default configuration values."""
        # Try to get values from settings if available, otherwise use hardcoded defaults
        try:
            enabled = getattr(settings, 'passthrough_enabled', True)
            base_path = getattr(settings, 'passthrough_base_path', '/passthrough')  
            default_timeout_ms = getattr(settings, 'passthrough_default_timeout_ms', 20000)
            pre_chain = getattr(settings, 'passthrough_default_plugin_chains_pre', ['deny_filter', 'regex_filter', 'pii_filter'])
            post_chain = getattr(settings, 'passthrough_default_plugin_chains_post', ['pii_filter'])
        except (ImportError, AttributeError):
            # Fallback if settings not available
            enabled = True
            base_path = '/passthrough'
            default_timeout_ms = 20000
            pre_chain = ['deny_filter', 'regex_filter', 'pii_filter'] 
            post_chain = ['pii_filter']
        
        defaults = {
            'enabled': enabled,
            'base_path': base_path,
            'default_timeout_ms': default_timeout_ms,
            'default_plugin_chains': {
                'pre': pre_chain,
                'post': post_chain
            }
        }
        
        for key, default_value in defaults.items():
            if key not in self._config:
                self._config[key] = default_value
    
    @property
    def enabled(self) -> bool:
        """Check if passthrough is enabled."""
        return self._config.get('enabled', True)
    
    @property
    def base_path(self) -> str:
        """Get the base path for passthrough endpoints."""
        return self._config.get('base_path', '/passthrough')
    
    @property
    def default_timeout_ms(self) -> int:
        """Get the default timeout in milliseconds."""
        return self._config.get('default_timeout_ms', 20000)
    
    @property
    def default_plugin_chains(self) -> Dict[str, List[str]]:
        """Get the default plugin chains for pre/post processing."""
        return self._config.get('default_plugin_chains', {
            'pre': ['deny_filter', 'regex_filter', 'pii_filter'],
            'post': ['pii_filter']
        })
    
    def get_pre_chain(self, tool_override: Optional[List[str]] = None) -> List[str]:
        """Get the pre-processing plugin chain.
        
        Args:
            tool_override: Tool-specific override chain
            
        Returns:
            List of plugin names to execute
        """
        if tool_override:
            return tool_override
        return self.default_plugin_chains.get('pre', [])
    
    def get_post_chain(self, tool_override: Optional[List[str]] = None) -> List[str]:
        """Get the post-processing plugin chain.
        
        Args:
            tool_override: Tool-specific override chain
            
        Returns:
            List of plugin names to execute
        """
        if tool_override:
            return tool_override  
        return self.default_plugin_chains.get('post', [])
    
    def validate_config(self) -> List[str]:
        """Validate the configuration and return any warnings.
        
        Returns:
            List of warning messages
        """
        warnings = []
        
        if not isinstance(self.enabled, bool):
            warnings.append("passthrough.enabled should be a boolean")
        
        if not isinstance(self.base_path, str) or not self.base_path.startswith('/'):
            warnings.append("passthrough.base_path should be a string starting with '/'")
        
        if not isinstance(self.default_timeout_ms, int) or self.default_timeout_ms <= 0:
            warnings.append("passthrough.default_timeout_ms should be a positive integer")
        
        chains = self.default_plugin_chains
        if not isinstance(chains, dict):
            warnings.append("passthrough.default_plugin_chains should be a dictionary")
        else:
            for chain_type in ['pre', 'post']:
                chain = chains.get(chain_type, [])
                if not isinstance(chain, list):
                    warnings.append(f"passthrough.default_plugin_chains.{chain_type} should be a list")
                elif not all(isinstance(plugin, str) for plugin in chain):
                    warnings.append(f"passthrough.default_plugin_chains.{chain_type} should contain only strings")
        
        return warnings
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for API responses.
        
        Returns:
            Configuration as dictionary
        """
        return {
            'enabled': self.enabled,
            'base_path': self.base_path,
            'default_timeout_ms': self.default_timeout_ms,
            'default_plugin_chains': self.default_plugin_chains.copy()
        }


# Global instance
passthrough_config = PassthroughConfig()


def get_passthrough_config() -> PassthroughConfig:
    """Get the global passthrough configuration instance.
    
    Returns:
        PassthroughConfig instance
    """
    return passthrough_config


def reload_passthrough_config() -> None:
    """Reload passthrough configuration from file.
    
    Useful for configuration updates without restart.
    """
    global passthrough_config
    passthrough_config = PassthroughConfig()
    logger.info("Passthrough configuration reloaded")


def validate_passthrough_config() -> List[str]:
    """Validate current passthrough configuration.
    
    Returns:
        List of warning messages, empty if configuration is valid
    """
    return passthrough_config.validate_config()