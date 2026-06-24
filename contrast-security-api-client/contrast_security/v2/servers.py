"""
Servers API endpoints for V2.
"""

from typing import Any, Dict, List, Optional
import requests


class V2ServersAPI:
    """Servers API client for V2 endpoints."""
    
    def __init__(self, client):
        """Initialize with reference to main client."""
        self.client = client
    
    def list(
        self,
        organization_id: Optional[str] = None,
        expand: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Get a list of servers (V2).
        
        Args:
            organization_id: Organization UUID
            expand: Properties to expand
            **kwargs: Additional query parameters
            
        Returns:
            Response containing server list
        """
        endpoint = f"/api/{organization_id}/servers"
        
        params = {
            'expand': ','.join(expand) if expand else None,
            **kwargs
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )