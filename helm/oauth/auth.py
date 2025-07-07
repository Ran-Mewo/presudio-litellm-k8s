"""
Main OAuth Authentication Handler for LiteLLM
"""
import logging
import importlib
from typing import Dict
from fastapi import Request
from litellm.proxy._types import UserAPIKeyAuth

from .config import config
from .providers.base import BaseOAuthProvider, InvalidTokenError, ProviderAPIError, ConfigurationError

logger = logging.getLogger(__name__)

# Cache for provider instances
_provider_cache: Dict[str, BaseOAuthProvider] = {}

def _get_provider_instance(provider_name: str) -> BaseOAuthProvider:
    """Get or create provider instance"""
    if provider_name not in _provider_cache:
        try:
            module = importlib.import_module(f"oauth.providers.{provider_name}")
            class_name = f"{provider_name.capitalize()}OAuthProvider"
            provider_class = getattr(module, class_name)
            _provider_cache[provider_name] = provider_class(config.get_provider_config())
        except (ImportError, AttributeError) as e:
            raise ConfigurationError(f"OAuth provider '{provider_name}' is not supported: {e}")

    return _provider_cache[provider_name]


async def user_api_key_auth(request: Request, api_key: str) -> UserAPIKeyAuth:
    """Custom OAuth authentication function for LiteLLM"""
    if not config.is_enabled():
        raise Exception("OAuth authentication is disabled")

    if not config.provider:
        raise Exception("OAuth provider not configured")

    # Allow health endpoints without authentication
    if request.url.path in ["/health", "/health/liveliness", "/health/readiness"]:
        return UserAPIKeyAuth(
            api_key="health-check",
            user_id="health",
            user_email=None,
            user_role="internal_user"
        )

    try:
        provider = _get_provider_instance(config.provider)
        token = provider.extract_token_from_request(request, api_key)

        # Check cache first
        user_info = provider.get_cached_user_info(token)
        if user_info is None: # Cache miss, validate with provider
            user_info = await provider.validate_token(token)
            provider.cache_user_info(token, user_info, config.cache_ttl)

        return UserAPIKeyAuth(
            api_key=token,
            user_id=user_info.user_id,
            user_email=user_info.email,
            user_role="customer", # Default Roles: 'proxy_admin', 'proxy_admin_viewer', 'org_admin', 'internal_user', 'internal_user_viewer', 'team', 'customer'
            metadata={
                "oauth_provider": config.provider,
                "username": user_info.username,
                "name": user_info.name,
                "avatar_url": user_info.avatar_url,
                **(user_info.extra or {})
            }
        )
    except (InvalidTokenError, ProviderAPIError, ConfigurationError) as e:
        logger.warning(f"OAuth authentication failed: {e}")
        raise Exception(f"Authentication failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected OAuth error: {e}")
        raise Exception(f"Authentication failed: {e}")

# Exported to be visible to litellm
__all__ = ["user_api_key_auth"]
