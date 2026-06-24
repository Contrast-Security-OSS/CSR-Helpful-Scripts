"""
Custom exceptions for the Contrast Security API client.
"""

from typing import Any, Dict, Optional


class ContrastAPIError(Exception):
    """Base exception for all Contrast API errors."""
    
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_data: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_data = response_data or {}

    def __str__(self) -> str:
        if self.status_code:
            return f"HTTP {self.status_code}: {self.message}"
        return self.message


class AuthenticationError(ContrastAPIError):
    """Raised when authentication fails (401 Unauthorized)."""
    pass


class AuthorizationError(ContrastAPIError):
    """Raised when authorization fails (403 Forbidden).""" 
    pass


class NotFoundError(ContrastAPIError):
    """Raised when a resource is not found (404 Not Found)."""
    pass


class ValidationError(ContrastAPIError):
    """Raised when request validation fails (400 Bad Request)."""
    pass


class RateLimitError(ContrastAPIError):
    """Raised when rate limit is exceeded (429 Too Many Requests)."""
    
    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        **kwargs: Any,
    ):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ServerError(ContrastAPIError):
    """Raised when server encounters an error (5xx Server Error)."""
    pass


class TimeoutError(ContrastAPIError):
    """Raised when a request times out."""
    pass


class NetworkError(ContrastAPIError):
    """Raised when a network error occurs."""
    pass


class ConfigurationError(ContrastAPIError):
    """Raised when there's a configuration error."""
    pass