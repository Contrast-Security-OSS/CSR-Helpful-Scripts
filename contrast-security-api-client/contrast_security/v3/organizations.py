"""
Organizations API endpoints for V3.
"""

from typing import Any, Dict, List, Optional, Union
import requests


class OrganizationsAPI:
    """Organizations API client for V3 endpoints."""
    
    def __init__(self, client):
        """Initialize with reference to main client."""
        self.client = client
    
    def list(self) -> requests.Response:
        """Get a list of organizations accessible to the user."""
        endpoint = "/api/ng/organizations"
        return self.client.get(endpoint)
    
    def get(
        self,
        organization_id: str,
        expand: Optional[List[str]] = None,
    ) -> requests.Response:
        """Get details for a specific organization."""
        endpoint = f"/api/ng/{organization_id}"
        
        params = {
            'expand': ','.join(expand) if expand else None,
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )