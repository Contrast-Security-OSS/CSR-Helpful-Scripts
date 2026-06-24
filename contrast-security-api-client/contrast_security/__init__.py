"""
Contrast Security API Client

A comprehensive Python client library for the Contrast Security API.
"""

__version__ = "1.0.0"
__author__ = "Contrast Security Community"
__email__ = "support@contrastsecurity.com"

from .client import ContrastAPI
from .exceptions import (
    ContrastAPIError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    RateLimitError,
    ServerError,
)

__all__ = [
    "ContrastAPI",
    "ContrastAPIError", 
    "AuthenticationError",
    "AuthorizationError", 
    "NotFoundError",
    "ValidationError",
    "RateLimitError",
    "ServerError",
]