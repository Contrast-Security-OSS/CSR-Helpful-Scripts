"""
Reports API endpoints for V3.
"""

from typing import Any, Dict, List, Optional
import requests


class ReportsAPI:
    """Reports API client for V3 endpoints."""
    
    def __init__(self, client):
        self.client = client
    
    def download(
        self,
        report_id: str,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """Download a report."""
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/reports/{report_id}"
        return self.client.get(endpoint, organization_id=organization_id)