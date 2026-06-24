"""
Servers API endpoints for V3.
"""

from typing import Any, Dict, List, Optional, Union
import requests


class ServersAPI:
    """Servers API client for V3 endpoints."""
    
    def __init__(self, client):
        """Initialize with reference to main client."""
        self.client = client
    
    def list(
        self,
        organization_id: Optional[str] = None,
        expand: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        q: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Get a list of servers."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/servers"
        
        params = {
            'expand': ','.join(expand) if expand else None,
            'limit': limit,
            'offset': offset,
            'sort': sort,
            'q': q,
            **kwargs
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )
    
    def get(
        self,
        server_id: str,
        organization_id: Optional[str] = None,
        expand: Optional[List[str]] = None,
    ) -> requests.Response:
        """Get details for a specific server."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/servers/{server_id}"
        
        params = {
            'expand': ','.join(expand) if expand else None,
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )