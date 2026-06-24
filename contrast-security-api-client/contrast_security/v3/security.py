"""
Security API endpoints for V3.
"""

from typing import Any, Dict, List, Optional
import requests


class SecurityAPI:
    """Security API client for V3 endpoints."""
    
    def __init__(self, client):
        self.client = client
    
    def get_controls(
        self,
        organization_id: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Get security controls."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/security/controls"
        return self.client.get(endpoint, organization_id=organization_id, params=kwargs)