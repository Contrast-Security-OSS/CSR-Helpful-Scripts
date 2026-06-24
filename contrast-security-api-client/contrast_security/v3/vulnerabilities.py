"""
Vulnerabilities (Traces) API endpoints for V3.
"""

from typing import Any, Dict, List, Optional, Union
import requests

from ..utils import build_url


class VulnerabilitiesAPI:
    """Vulnerabilities/Traces API client for V3 endpoints."""
    
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
        severities: Optional[List[str]] = None,
        statuses: Optional[List[str]] = None,
        ruleNames: Optional[List[str]] = None,
        environments: Optional[List[str]] = None,
        servers: Optional[List[str]] = None,
        startDate: Optional[Union[str, int]] = None,
        endDate: Optional[Union[str, int]] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Get a list of vulnerabilities (traces).
        
        Args:
            organization_id: Organization UUID
            expand: Properties to expand (application, servers, request, etc.)
            limit: Maximum number of results
            offset: Offset for pagination
            sort: Sort criteria
            q: Search query
            quickFilter: Quick filter name
            filterText: Filter text
            applicationIds: Filter by application IDs
            severities: Filter by severities (Critical, High, Medium, Low, Note)
            statuses: Filter by statuses (Reported, Suspicious, Confirmed, etc.)
            ruleNames: Filter by rule names
            environments: Filter by environments
            servers: Filter by server IDs
            startDate: Start date filter (timestamp or date string)
            endDate: End date filter (timestamp or date string)
            **kwargs: Additional query parameters
            
        Returns:
            Response containing vulnerability list
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces"
        params = {
            'expand': ','.join(expand) if expand else None,
            'limit': limit,
            'offset': offset,
            'sort': sort,
            'q': q,
            'quickFilter': quickFilter,
            'filterText': filterText,
            'applicationIds': ','.join(applicationIds) if applicationIds else None,
            'severities': ','.join(severities) if severities else None,
            'statuses': ','.join(statuses) if statuses else None,
            'ruleNames': ','.join(ruleNames) if ruleNames else None,
            'environments': ','.join(environments) if environments else None,
            'servers': ','.join(servers) if servers else None,
            'startDate': startDate,
            'endDate': endDate,
            **kwargs
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )
    
    def list_by_application(
        self,
        application_id: str,
        organization_id: Optional[str] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Get vulnerabilities for a specific application.
        
        Args:
            application_id: Application UUID
            organization_id: Organization UUID
            **kwargs: Additional query parameters (same as list method)
            
        Returns:
            Response containing application vulnerabilities
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces/{application_id}"
        # Extract common parameters
        params = {
            'expand': ','.join(kwargs.pop('expand', [])) if 'expand' in kwargs else None,
            'limit': kwargs.pop('limit', None),
            'offset': kwargs.pop('offset', None),
            'sort': kwargs.pop('sort', None),
            'q': kwargs.pop('q', None),
            'quickFilter': kwargs.pop('quickFilter', None),
            'filterText': kwargs.pop('filterText', None),
            'severities': ','.join(kwargs.pop('severities', [])) if 'severities' in kwargs else None,
            'statuses': ','.join(kwargs.pop('statuses', [])) if 'statuses' in kwargs else None,
            **kwargs
        }
        
        print(f"Fetching vulnerabilities with this endpoint: {endpoint}")

        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )
    
    def get(
        self,
        trace_id: str,
        organization_id: Optional[str] = None,
        expand: Optional[List[str]] = None,
    ) -> requests.Response:
        """
        Get details for a specific vulnerability.
        
        Args:
            trace_id: Vulnerability/trace UUID
            organization_id: Organization UUID
            expand: Properties to expand (application, request, events, etc.)
            
        Returns:
            Response containing vulnerability details
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces/{trace_id}"
        params = {
            'expand': ','.join(expand) if expand else None,
        }
        
        return self.client.get(
            endpoint,
            organization_id=organization_id,
            params=params
        )
    
    def mark_status(
        self,
        trace_id: str,
        status: str,
        organization_id: Optional[str] = None,
        substatus: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> requests.Response:
        """
        Mark the status of a vulnerability.
        
        Args:
            trace_id: Vulnerability/trace UUID
            status: New status (Reported, Suspicious, Confirmed, Fixed, etc.)
            organization_id: Organization UUID
            substatus: Sub-status for additional classification
            comment: Optional comment explaining the status change
            
        Returns:
            Response confirming status update
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces/{trace_id}/mark"
        data = {
            'status': status,
            'substatus': substatus,
            'comment': comment,
        }
        
        # Remove None values
        data = {k: v for k, v in data.items() if v is not None}
        
        return self.client.put(
            endpoint,
            organization_id=organization_id,
            json_data=data
        )
    
    def bulk_mark_status(
        self,
        trace_ids: List[str],
        status: str,
        organization_id: Optional[str] = None,
        substatus: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> requests.Response:
        """
        Bulk mark status for multiple vulnerabilities.
        
        Args:
            trace_ids: List of vulnerability/trace UUIDs
            status: New status
            organization_id: Organization UUID
            substatus: Sub-status for additional classification
            comment: Optional comment explaining the status change
            
        Returns:
            Response containing bulk update results
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/orgtraces/mark"
        data = {
            'traces': trace_ids,
            'status': status,
            'substatus': substatus,
            'comment': comment,
        }
        
        # Remove None values
        data = {k: v for k, v in data.items() if v is not None}
        
        return self.client.put(
            endpoint,
            organization_id=organization_id,
            json_data=data
        )
    
    def get_events(
        self,
        trace_id: str,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Get events (story) for a specific vulnerability.
        
        Args:
            trace_id: Vulnerability/trace UUID
            organization_id: Organization UUID
            
        Returns:
            Response containing vulnerability events/story
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces/{trace_id}/events"
        return self.client.get(
            endpoint,
            organization_id=organization_id
        )
    
    def get_notes(
        self,
        trace_id: str,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Get notes for a specific vulnerability.
        
        Args:
            trace_id: Vulnerability/trace UUID
            organization_id: Organization UUID
            
        Returns:
            Response containing vulnerability notes
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces/{trace_id}/notes"
        return self.client.get(
            endpoint,
            organization_id=organization_id
        )
    
    def add_note(
        self,
        trace_id: str,
        note: str,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Add a note to a vulnerability.
        
        Args:
            trace_id: Vulnerability/trace UUID
            note: Note content
            organization_id: Organization UUID
            
        Returns:
            Response containing created note
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces/{trace_id}/notes"
        data = {
            'note': note,
        }
        
        return self.client.post(
            endpoint,
            organization_id=organization_id,
            json_data=data
        )
    
    def get_http_request(
        self,
        trace_id: str,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Get HTTP request details for a vulnerability.
        
        Args:
            trace_id: Vulnerability/trace UUID
            organization_id: Organization UUID
            
        Returns:
            Response containing HTTP request details
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces/{trace_id}/httprequest"
        return self.client.get(
            endpoint,
            organization_id=organization_id
        )
    
    def delete(
        self,
        trace_id: str,
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Delete a vulnerability.
        
        Args:
            trace_id: Vulnerability/trace UUID
            organization_id: Organization UUID
            
        Returns:
            Response confirming deletion
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/traces/{trace_id}"
        return self.client.delete(
            endpoint,
            organization_id=organization_id
        )
    
    def bulk_delete(
        self,
        trace_ids: List[str],
        organization_id: Optional[str] = None,
    ) -> requests.Response:
        """
        Bulk delete multiple vulnerabilities.
        
        Args:
            trace_ids: List of vulnerability/trace UUIDs
            organization_id: Organization UUID
            
        Returns:
            Response containing bulk deletion results
        """
        org_id = organization_id or self.client.organization_id
        endpoint = f"/api/ng/{org_id}/orgtraces/delete"
        data = {
            'traces': trace_ids,
        }
        
        return self.client.put(
            endpoint,
            organization_id=organization_id,
            json_data=data
        )