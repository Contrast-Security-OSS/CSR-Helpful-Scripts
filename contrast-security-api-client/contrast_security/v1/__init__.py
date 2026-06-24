"""
V1 API module for Contrast Security API (legacy).

This module provides access to V1 API endpoints for legacy compatibility.
"""

from .applications import V1ApplicationsAPI


class V1API:
    """V1 API client providing access to legacy V1 endpoints."""
    
    def __init__(self, client):
        """Initialize V1 API with reference to main client."""
        self.client = client
        
        # Initialize V1 API endpoint modules
        self.applications = V1ApplicationsAPI(client)