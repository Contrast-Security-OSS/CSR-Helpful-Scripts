"""
V2 API module for Contrast Security API.

This module provides access to V2 API endpoints for legacy compatibility.
"""

from .applications import V2ApplicationsAPI
from .vulnerabilities import V2VulnerabilitiesAPI  
from .servers import V2ServersAPI


class V2API:
    """V2 API client providing access to V2 endpoints."""
    
    def __init__(self, client):
        """Initialize V2 API with reference to main client."""
        self.client = client
        
        # Initialize V2 API endpoint modules
        self.applications = V2ApplicationsAPI(client)
        self.vulnerabilities = V2VulnerabilitiesAPI(client)
        self.servers = V2ServersAPI(client)