"""
Applications API endpoints for V3.
"""

from typing import Any, Dict, List, Optional, Union
import requests

from ..utils import build_url


class ApplicationsAPI:
    """Applications API client for V3 endpoints."""
    
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
        q: Optional[str] = None,
        quickFilter: Optional[str] = None,
        filterText: Optional[str] = None,
        applicationIds: Optional[List[str]] = None,
        teamServerApplications: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Get a list of applications.
        
        Args:
            organization_id: Organization UUID  
            expand: Properties to expand (servers, scores, licenses, etc.)
            limit: Maximum number of results
            offset: Offset for pagination
            sort: Sort criteria
            q: Search query
            quickFilter: Quick filter name
            filterText: Filter text
            applicationIds: Specific application IDs to include
            teamServerApplications: Include TeamServer applications
            **kwargs: Additional query parameters
            
        Returns:
            Response containing application list
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications"
        params = {
            'expand': ','.join(expand) if expand else None,
            'limit': limit,
            'offset': offset,
            'sort': sort,
            'q': q,
            'quickFilter': quickFilter,
            'filterText': filterText,
            'applicationIds': ','.join(applicationIds) if applicationIds else None,
            'teamServerApplications': teamServerApplications,
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
        Get details for a specific application.
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            expand: Properties to expand
            
        Returns:
            Response containing application details
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications/{application_id}"
        params = {
            'expand': ','.join(expand) if expand else None,
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )
    
    def create(
        self,
        name: str,
        language: str,
        organization_id: Optional[str] = None,
        path: Optional[str] = None,
        importance: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Create a new application.
        
        Args:
            name: Application name
            language: Programming language
            organization_id: Organization UUID
            path: Application path/context root
            importance: Application importance level
            tags: Application tags
            metadata: Application metadata
            **kwargs: Additional application properties
            
        Returns:
            Response containing created application
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications"
        data = {
            'name': name,
            'language': language,
            'path': path,
            'importance': importance,
            'tags': tags,
            'metadata': metadata,
            **kwargs
        }
        
        return self.client.post(
            endpoint,
            organization_id=organization_id,
            json_data=data
        )
    
    def update(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
        name: Optional[str] = None,
        importance: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Update an existing application.
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            name: Updated application name
            importance: Updated importance level
            tags: Updated application tags
            metadata: Updated application metadata
            **kwargs: Additional application properties
            
        Returns:
            Response containing updated application
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications/{application_id}"
        data = {
            'name': name,
            'importance': importance,
            'tags': tags,
            'metadata': metadata,
            **kwargs
        }
        
        # Remove None values
        data = {k: v for k, v in data.items() if v is not None}
        
        return self.client.put(
            endpoint,
            organization_id=organization_id,
            json_data=data
        )
    
    def delete(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Delete an application.
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            
        Returns:
            Response confirming deletion
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications/{application_id}"
        return self.client.delete(
            endpoint,
            organization_id=organization_id
        )
    
    def get_libraries(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
        expand: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Get libraries for a specific application.
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            expand: Properties to expand
            limit: Maximum number of results
            offset: Offset for pagination  
            sort: Sort criteria
            **kwargs: Additional query parameters
            
        Returns:
            Response containing application libraries
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications/{application_id}/libraries"
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
    
    def get_servers(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
        expand: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Get servers for a specific application.
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            expand: Properties to expand
            **kwargs: Additional query parameters
            
        Returns:
            Response containing application servers
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications/{application_id}/servers"
        params = {
            'expand': ','.join(expand) if expand else None,
            **kwargs
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )
    
    def get_scores(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Get security scores for a specific application.
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            
        Returns:
            Response containing application scores
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications/{application_id}/scores"
        return self.client.get(
            endpoint,
            organization_id=organization_id
        )
    
    def bulk_update(
        self,
        application_updates: List[Dict[str, Any]],
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Bulk update multiple applications.
        
        Args:
            application_updates: List of application update objects
            organization_id: Organization UUID
            
        Returns:
            Response containing bulk update results
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/applications/bulk"
        data = {
            'applications': application_updates
        }
        
        return self.client.put(
            endpoint,
            organization_id=organization_id,
            json_data=data
        )