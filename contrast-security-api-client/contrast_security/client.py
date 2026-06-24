"""
Main API client for the Contrast Security API.
"""

import requests
from typing import Any, Dict, Optional, Union
from urllib.parse import urljoin

from .auth import ContrastAuth, create_auth_from_file, create_auth_from_fetch_creds, create_auth_from_creds_file
from .exceptions import (
    ContrastAPIError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    RateLimitError,
    ServerError,
    TimeoutError,
    NetworkError,
)
from .utils import build_url, retry_with_backoff

# Import API version modules (will be created in next steps)
from .v3 import V3API
from .v2 import V2API
from .v1 import V1API


class ContrastAPI:
    """
    Main client for interacting with the Contrast Security API.
    
    This client provides access to all API versions and handles authentication,
    error handling, and common functionality.
    """
    
    def __init__(
        self,
        base_url: str = "https://app.contrastsecurity.com",
        api_key: Optional[str] = None,
        service_key: Optional[str] = None,
        username: Optional[str] = None,
        organization_id: Optional[str] = None,
        credentials_file: Optional[str] = None,
        auth: Optional[ContrastAuth] = None,
        use_fetch_creds: bool = False,
        interactive_creds: bool = True,
        creds_filename: str = ".creds",
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
    ):
        """
        Initialize the Contrast API client.
        
        Args:
            base_url: Base URL for the Contrast instance
            api_key: API key for authentication
            service_key: Service key for authentication
            username: Optional username for user-specific operations
            organization_id: Default organization ID for scoped operations
            credentials_file: Path to credentials file (alternative to keys)
            auth: Pre-configured ContrastAuth instance
            use_fetch_creds: Use fetch_creds.py system for authentication
            interactive_creds: Allow interactive prompting when using fetch_creds
            creds_filename: Name of .creds file when using fetch_creds (default: ".creds")
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verify_ssl: Whether to verify SSL certificates
            user_agent: Custom user agent string
        """
        # Initialize credential info storage
        self._credential_info = {}
        
        # Set up authentication based on provided options
        if auth:
            # Use pre-configured auth object
            self.auth = auth
            self.base_url = base_url.rstrip('/')
            self.organization_id = organization_id
        elif use_fetch_creds:
            # Use fetch_creds.py system
            try:
                if interactive_creds:
                    self.auth, self._credential_info = create_auth_from_fetch_creds(interactive=True)
                else:
                    self.auth, self._credential_info = create_auth_from_creds_file(creds_filename)
                
                # Use base_url and org_id from credentials if not provided
                self.base_url = (base_url or self._credential_info.get('contrast_url', 'https://app.contrastsecurity.com')).rstrip('/')
                self.organization_id = organization_id or self._credential_info.get('org_id')
                
            except (ImportError, ValueError, FileNotFoundError) as e:
                raise ValueError(f"Failed to initialize with fetch_creds: {e}")
        elif credentials_file:
            # Use credentials file
            self.auth = create_auth_from_file(credentials_file, username)
            self.base_url = base_url.rstrip('/')
            self.organization_id = organization_id
        elif api_key and service_key:
            # Use direct credentials
            self.auth = ContrastAuth(api_key, service_key, username)
            self.base_url = base_url.rstrip('/')
            self.organization_id = organization_id
        else:
            raise ValueError(
                "Must provide one of: "
                "(api_key and service_key), credentials_file, auth object, or use_fetch_creds=True"
            )
        
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        
        # Set up session
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Set user agent
        default_user_agent = "contrast-security-api-client/1.0.0"
        self.session.headers.update({
            "User-Agent": user_agent or default_user_agent
        })
        
        # Initialize API version clients
        self.v3 = V3API(self)
        self.v2 = V2API(self) 
        self.v1 = V1API(self)
        
        # Convenience aliases for most commonly used v3 endpoints
        self.applications = self.v3.applications
        self.vulnerabilities = self.v3.vulnerabilities
        self.servers = self.v3.servers
        self.libraries = self.v3.libraries
        self.organizations = self.v3.organizations
        self.users = self.v3.users
        self.reports = self.v3.reports
        self.traces = self.v3.traces
        self.attacks = self.v3.attacks
    
    @property
    def credential_info(self) -> Dict[str, str]:
        """Get credential information if available from fetch_creds system."""
        return self._credential_info.copy()
    
    @classmethod
    def from_fetch_creds(
        cls,
        interactive: bool = True,
        creds_filename: str = ".creds",
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
    ) -> 'ContrastAPI':
        """
        Create ContrastAPI instance using fetch_creds.py system.
        
        This is a convenience method that automatically handles credential loading
        from the CSR-Helpful-Scripts system.
        
        Args:
            interactive: Allow interactive prompting for missing credentials
            creds_filename: Name of .creds file (default: ".creds")
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verify_ssl: Whether to verify SSL certificates
            user_agent: Custom user agent string
            
        Returns:
            Configured ContrastAPI instance
            
        Example:
            # Interactive mode (prompts for missing credentials)
            client = ContrastAPI.from_fetch_creds()
            
            # Non-interactive mode (only uses .creds file)
            client = ContrastAPI.from_fetch_creds(interactive=False)
        """
        return cls(
            use_fetch_creds=True,
            interactive_creds=interactive,
            creds_filename=creds_filename,
            timeout=timeout,
            max_retries=max_retries,
            verify_ssl=verify_ssl,
            user_agent=user_agent,
        )
    
    def request(
        self,
        method: str,
        endpoint: str,
        organization_id: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Make an authenticated request to the Contrast API.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint path
            organization_id: Organization ID for scoped requests
            params: Query parameters
            json_data: JSON data for request body
            data: Raw data for request body
            headers: Additional headers
            timeout: Request timeout override
            **kwargs: Additional arguments passed to requests
            
        Returns:
            requests.Response object
            
        Raises:
            ContrastAPIError: For various API errors
        """
        # Build complete URL
        url = urljoin(self.base_url + '/', endpoint.lstrip('/'))
        
        # Prepare headers
        auth_headers = self.auth.get_headers(
            organization_id or self.organization_id
        )
        if headers:
            auth_headers.update(headers)
        
        # Prepare request arguments
        request_kwargs = {
            'timeout': timeout or self.timeout,
            'headers': auth_headers,
            'params': params,
            **kwargs
        }
        
        if json_data is not None:
            request_kwargs['json'] = json_data
        elif data is not None:
            request_kwargs['data'] = data
        
        # Define the request function for retry logic
        def make_request():
            try:
                response = self.session.request(method, url, **request_kwargs)
                self._handle_response_errors(response)
                return response
            except requests.exceptions.Timeout as e:
                raise TimeoutError(f"Request timed out: {e}")
            except requests.exceptions.ConnectionError as e:
                raise NetworkError(f"Network error: {e}")
            except requests.exceptions.RequestException as e:
                raise ContrastAPIError(f"Request failed: {e}")
        
        # Execute request with retry logic
        return retry_with_backoff(
            make_request,
            max_retries=self.max_retries,
        )
    
    def _handle_response_errors(self, response: requests.Response) -> None:
        """
        Handle HTTP response errors and raise appropriate exceptions.
        
        Args:
            response: requests.Response object
            
        Raises:
            ContrastAPIError: For various HTTP error codes
        """
        if response.status_code < 400:
            return
        
        try:
            error_data = response.json()
            error_message = error_data.get('message', response.text)
        except ValueError:
            error_message = response.text or f"HTTP {response.status_code} error"
        
        if response.status_code == 401:
            raise AuthenticationError(
                error_message,
                status_code=response.status_code,
                response_data=error_data if 'error_data' in locals() else None
            )
        elif response.status_code == 403:
            raise AuthorizationError(
                error_message,
                status_code=response.status_code,
                response_data=error_data if 'error_data' in locals() else None
            )
        elif response.status_code == 404:
            raise NotFoundError(
                error_message,
                status_code=response.status_code,
                response_data=error_data if 'error_data' in locals() else None
            )
        elif response.status_code == 400:
            raise ValidationError(
                error_message,
                status_code=response.status_code,
                response_data=error_data if 'error_data' in locals() else None
            )
        elif response.status_code == 429:
            retry_after = response.headers.get('Retry-After')
            raise RateLimitError(
                error_message,
                status_code=response.status_code,
                retry_after=int(retry_after) if retry_after else None,
                response_data=error_data if 'error_data' in locals() else None
            )
        elif response.status_code >= 500:
            raise ServerError(
                error_message,
                status_code=response.status_code,
                response_data=error_data if 'error_data' in locals() else None
            )
        else:
            raise ContrastAPIError(
                error_message,
                status_code=response.status_code,
                response_data=error_data if 'error_data' in locals() else None
            )
    
    def get(self, endpoint: str, **kwargs: Any) -> requests.Response:
        """Make a GET request."""
        return self.request('GET', endpoint, **kwargs)
    
    def post(self, endpoint: str, **kwargs: Any) -> requests.Response:
        """Make a POST request."""
        return self.request('POST', endpoint, **kwargs)
    
    def put(self, endpoint: str, **kwargs: Any) -> requests.Response:
        """Make a PUT request.""" 
        return self.request('PUT', endpoint, **kwargs)
    
    def delete(self, endpoint: str, **kwargs: Any) -> requests.Response:
        """Make a DELETE request."""
        return self.request('DELETE', endpoint, **kwargs)
    
    def patch(self, endpoint: str, **kwargs: Any) -> requests.Response:
        """Make a PATCH request."""
        return self.request('PATCH', endpoint, **kwargs)
    
    def set_organization(self, organization_id: str) -> None:
        """
        Set the default organization ID for subsequent requests.
        
        Args:
            organization_id: Organization ID to use as default
        """
        self.organization_id = organization_id
    
    def get_organization(self) -> Optional[str]:
        """
        Get the current default organization ID.
        
        Returns:
            Current default organization ID or None
        """
        return self.organization_id