"""
Libraries API endpoints for V3.
"""

from typing import Any, Dict, List, Optional, Union
import requests


class LibrariesAPI:
    """Libraries API client for V3 endpoints."""
    
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
        **kwargs: Any,
    ) -> requests.Response:
        """Get a list of libraries."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/libraries"
        params = {
            'expand': ','.join(expand) if expand else None,
            'limit': limit,
            'offset': offset,
            'sort': sort,
            **kwargs
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )