"""
Applications API endpoints for V1 (legacy).
"""

from typing import Any, Dict, List, Optional
import requests


class V1ApplicationsAPI:
    """Applications API client for V1 endpoints (legacy)."""
    
    def __init__(self, client):
        """Initialize with reference to main client."""
        self.client = client
    
    def list(
        self,
        organization_id: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Get a list of applications (V1 legacy).
        
        Args:
            organization_id: Organization UUID
            **kwargs: Additional query parameters
            
        Returns:
            Response containing application list
        """
        endpoint = f"/api/v1/{organization_id}/applications"
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=kwargs
        )