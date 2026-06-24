"""
Metadata API endpoints for V3.
"""

from typing import Any, Dict, List, Optional
import requests


class MetadataAPI:
    """Metadata API client for V3 endpoints."""
    
    def __init__(self, client):
        self.client = client
    
    def list_fields(
        self,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """Get metadata fields."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/metadata/fields"
        return self.client.get(endpoint, organization_id=organization_id)