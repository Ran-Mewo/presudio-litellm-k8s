"""
Base OAuth Provider Interface
"""
import hashlib
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class UserInfo:
    """User information from OAuth provider"""
    user_id: str
    username: str
    email: Optional[str] = None
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


class OAuthProviderError(Exception):
    """Base exception for OAuth provider errors"""
    pass


class InvalidTokenError(OAuthProviderError):
    """Token is invalid or expired"""
    pass


class ProviderAPIError(OAuthProviderError):
    """Error communicating with OAuth provider API"""
    pass


class ConfigurationError(OAuthProviderError):
    """OAuth provider configuration error"""
    pass


class BaseOAuthProvider(ABC):
    """Abstract base class for OAuth providers"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize OAuth provider

        Args:
            config: Provider-specific configuration
        """
        self.config = config
        self._cache: Dict[str, Tuple[UserInfo, float]] = {}  # Cache: {hash: (user_info, expiry_time)}
        self._validate_config()
    
    @abstractmethod
    def _validate_config(self):
        """Validate provider configuration"""
        pass
    
    @abstractmethod
    def extract_token_from_request(self, request, api_key: str) -> str:
        """
        Extract OAuth token from request in provider-specific way

        Args:
            request: FastAPI Request object
            api_key: API key parameter from LiteLLM

        Returns:
            Extracted token

        Raises:
            InvalidTokenError: If token cannot be extracted or is invalid format
        """
        pass

    @abstractmethod
    async def validate_token(self, token: str) -> UserInfo:
        """
        Validate OAuth token and return user information

        Args:
            token: OAuth access token

        Returns:
            UserInfo object with user details

        Raises:
            InvalidTokenError: If token is invalid
            ProviderAPIError: If API call fails
        """
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Get provider name"""
        pass

    def get_user_cache_key(self, token: str) -> str:
        """Generate cache key for user info using token hash"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        return f"oauth:{self.get_provider_name()}:user:{token_hash}"

    def get_cached_user_info(self, token: str) -> Optional[UserInfo]:
        """Get cached user info if valid and not expired"""
        cache_key = self.get_user_cache_key(token)
        if cache_key in self._cache:
            user_info, expiry_time = self._cache[cache_key]
            if time.time() < expiry_time:
                return user_info
            del self._cache[cache_key]  # Remove expired entry
        return None

    def cache_user_info(self, token: str, user_info: UserInfo, cache_ttl: int):
        """Cache user info with expiry time"""
        cache_key = self.get_user_cache_key(token)
        expiry_time = time.time() + cache_ttl
        self._cache[cache_key] = (user_info, expiry_time)
