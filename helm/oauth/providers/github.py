"""
GitHub OAuth Provider Implementation
"""
import logging
import re
import aiohttp
from typing import Dict, Any
from .base import BaseOAuthProvider, UserInfo, InvalidTokenError, ProviderAPIError, ConfigurationError

logger = logging.getLogger(__name__)

class GithubOAuthProvider(BaseOAuthProvider):
    """GitHub OAuth provider implementation"""

    def __init__(self, config: Dict[str, Any]):
        config.setdefault("api_base", "https://api.github.com")
        super().__init__(config)

    def _validate_config(self):
        """Validate GitHub configuration"""
        api_base = self.config.get("api_base", "")
        if not api_base.startswith(("http://", "https://")):
            raise ConfigurationError(f"Invalid GitHub API base URL: {api_base}")

    def get_provider_name(self) -> str:
        return "github"
    
    def extract_token_from_request(self, request, api_key: str) -> str:
        """Extract GitHub OAuth token from request"""
        # Try Authorization header first
        auth_header = request.headers.get("authorization", "").strip()
        if auth_header:
            # Match "Bearer <token>" or "token <token>"
            match = re.match(r'^(?:Bearer|token)\s+(.+)$', auth_header, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        # Fallback to api_key parameter
        if api_key:
            return api_key.strip()

        raise InvalidTokenError("No GitHub token found in request")

    async def validate_token(self, token: str) -> UserInfo:
        """Validate GitHub OAuth token and return user information"""
        if not token:
            raise InvalidTokenError("Token is required")

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "LiteLLM-OAuth/1.0"
        }

        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.config['api_base']}/user"
                async with session.get(url, headers=headers) as response:
                    await self._handle_response_errors(response)
                    user_data = await response.json()
                    return self._create_user_info(user_data)

        except aiohttp.ClientError as e:
            raise ProviderAPIError(f"Failed to connect to GitHub API: {e}")
        except (InvalidTokenError, ProviderAPIError):
            raise
        except Exception as e:
            raise ProviderAPIError(f"Unexpected error during GitHub token validation: {e}")

    @staticmethod
    async def _handle_response_errors(response):
        """Handle GitHub API response errors"""
        if response.status in (401, 403):
            raise InvalidTokenError("Invalid or expired GitHub token")
        elif response.status != 200:
            raise ProviderAPIError(f"GitHub API returned status {response.status}")

    @staticmethod
    def _create_user_info(user_data: Dict[str, Any]) -> UserInfo:
        """Create UserInfo from GitHub API response"""
        user_id = str(user_data.get("id", ""))
        username = user_data.get("login", "")

        if not user_id or not username:
            raise ProviderAPIError("Invalid user data received from GitHub API")

        return UserInfo(
            user_id=user_id,
            username=username,
            email=user_data.get("email"),
            name=user_data.get("name"),
            avatar_url=user_data.get("avatar_url"),
            extra={
                "github_id": user_data.get("id"),
                "github_login": user_data.get("login"),
                "github_type": user_data.get("type")
            }
        )
