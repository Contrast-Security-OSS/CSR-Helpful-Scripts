"""
Coverage API endpoints for V3.
"""

from typing import Any, Dict, List, Optional
import requests


class CoverageAPI:
    """Coverage API client for V3 endpoints."""
    
    def __init__(self, client):
        self.client = client
    
    def get_route_coverage(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Get route coverage for an application."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications/{application_id}/route-coverage"
        return self.client.get(endpoint, organization_id=organization_id, params=kwargs)