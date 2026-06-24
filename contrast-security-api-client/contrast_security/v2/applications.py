"""
Applications API endpoints for V2.
"""

from typing import Any, Dict, List, Optional
import requests


class V2ApplicationsAPI:
    """Applications API client for V2 endpoints."""
    
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
        Get a list of applications (V2).
        
        Args:
            organization_id: Organization UUID
            expand: Properties to expand
            **kwargs: Additional query parameters
            
        Returns:
            Response containing application list
        """
        endpoint = f"/api/{organization_id}/applications"
        
        params = {
            'expand': ','.join(expand) if expand else None,
            **kwargs
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )
    
    def get(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
        expand: Optional[List[str]] = None,
    ) -> requests.Response:
        """
        Get details for a specific application (V2).
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            expand: Properties to expand
            
        Returns:
            Response containing application details
        """
        endpoint = f"/api/{organization_id}/applications/{application_id}"
        
        params = {
            'expand': ','.join(expand) if expand else None,
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )