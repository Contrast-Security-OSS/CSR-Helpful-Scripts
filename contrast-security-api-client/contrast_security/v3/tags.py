"""
Tags API endpoints for V3.
"""

from typing import Any, Dict, List, Optional
import requests


class TagsAPI:
    """Tags API client for V3 endpoints."""
    
    def __init__(self, client):
        self.client = client
    
    def list(
        self,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """Get all tags."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/tags"
        return self.client.get(endpoint, organization_id=organization_id)