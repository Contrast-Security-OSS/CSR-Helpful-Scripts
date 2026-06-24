"""
Attacks API endpoints for V3 (RASP functionality).
"""

from typing import Any, Dict, List, Optional
import requests


class AttacksAPI:
    """Attacks API client for V3 endpoints (RASP)."""
    
    def __init__(self, client):
        self.client = client
    
    def list(
        self,
        organization_id: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Get a list of attacks."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/attacks"
        return self.client.get(endpoint, organization_id=organization_id, params=kwargs)