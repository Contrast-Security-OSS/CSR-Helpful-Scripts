"""
Vulnerabilities API endpoints for V2.
"""

from typing import Any, Dict, List, Optional
import requests


class V2VulnerabilitiesAPI:
    """Vulnerabilities API client for V2 endpoints."""
    
    def __init__(self, client):
        """Initialize with reference to main client."""
        self.client = client
    
    def list_by_application(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Get vulnerabilities for a specific application (V2).
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            **kwargs: Additional query parameters
            
        Returns:
            Response containing application vulnerabilities
        """
        endpoint = f"/api/{organization_id}/traces/{application_id}"
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=kwargs
        )
    
    def get(
        self,
        application_id: str,
        trace_id: str,
        organization_id: Optional[str] = None,
        expand: Optional[List[str]] = None,
    ) -> requests.Response:
        """
        Get details for a specific vulnerability (V2).
        
        Args:
            application_id: Application UUID
            trace_id: Vulnerability/trace UUID
            organization_id: Organization UUID
            expand: Properties to expand
            
        Returns:
            Response containing vulnerability details
        """
        endpoint = f"/api/{organization_id}/traces/{application_id}/{trace_id}"
        
        params = {
            'expand': ','.join(expand) if expand else None,
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )