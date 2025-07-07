"""
OAuth Configuration Management for LiteLLM
"""
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class OAuthConfig:
    """OAuth configuration management"""

    def __init__(self):
        self.enabled = _get_bool_env("OAUTH_ENABLED", False)
        self.provider = _get_env("OAUTH_PROVIDER", "github").lower()
        self.cache_ttl = _get_int_env("OAUTH_CACHE_TTL", 300)  # 5 minutes default

        # Generic provider configuration - dynamically loaded from environment
        self.provider_config = self._load_provider_config()

        # Validate configuration
        self._validate()

    def _load_provider_config(self) -> Dict[str, Any]:
        """Load provider configuration from environment variables"""
        if not self.provider:
            return {}

        prefix = f"OAUTH_{self.provider.upper()}_"
        return {
            key[len(prefix):].lower(): value
            for key, value in os.environ.items()
            if key.startswith(prefix)
        }

    def _validate(self):
        """Validate OAuth configuration"""
        if self.enabled and not self.provider:
            raise ValueError("OAUTH_PROVIDER must be specified when OAuth is enabled")
    
    def get_provider_config(self) -> Dict[str, Any]:
        """Get configuration for the current provider"""
        return self.provider_config.copy()

    def is_enabled(self) -> bool:
        """Check if OAuth is enabled"""
        return self.enabled



def _get_env(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get environment variable value"""
    return os.environ.get(key, default)

def _get_bool_env(key: str, default: bool = False) -> bool:
    """Get boolean environment variable value"""
    value = os.environ.get(key, "").lower()
    return value in ("true", "1", "yes", "on") if value else default

def _get_int_env(key: str, default: int) -> int:
    """Get integer environment variable value"""
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        logger.warning(f"Invalid integer value for {key}, using default: {default}")
        return default



# Global configuration instance
config = OAuthConfig()
