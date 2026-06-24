"""
Authentication handling for the Contrast Security API.
"""

import base64
import os
import sys
from typing import Dict, Optional, Tuple

# Add parent directory to path to import fetch_creds
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from fetch_creds import get_credentials, read_creds_file
except ImportError:
    # Fallback if fetch_creds.py is not available
    get_credentials = None
    read_creds_file = None


class ContrastAuth:
    """Handles authentication for Contrast Security API requests."""
    
    def __init__(
        self,
        api_key: str,
        service_key: str,
        username: Optional[str] = None,
    ):
        """
        Initialize authentication handler.
        
        Args:
            api_key: The API key from your Contrast account
            service_key: The service key from your Contrast account  
            username: Optional username (for user session endpoints)
        """
        self.api_key = api_key
        self.service_key = service_key
        self.username = username
        
        # Create base64 encoded authorization header
        self._auth_header = self._create_auth_header()
    
    def _create_auth_header(self) -> str:
        """Create the base64 encoded authorization header."""
        # Always use username:service_key for Basic Auth (not api_key:service_key)
        if not self.username:
            raise ValueError("Username is required for Basic authentication")
        auth_string = f"{self.username}:{self.service_key}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        return f"Basic {encoded_auth}"
    
    def get_headers(self, organization_id: Optional[str] = None) -> Dict[str, str]:
        """
        Get authentication headers for API requests.
        
        Args:
            organization_id: Optional organization ID for scoped requests
            
        Returns:
            Dictionary of authentication headers
        """
        headers = {
            "Authorization": self._auth_header,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "API-Key": self.api_key,
        }
        
        if organization_id:
            headers["Organization"] = organization_id
            
        return headers
    
    def get_auth_tuple(self) -> Tuple[str, str]:
        """
        Get authentication as a tuple for requests.auth.
        
        Returns:
            Tuple of (username/api_key, service_key)
        """
        return (self.username or self.api_key, self.service_key)


def create_auth_from_file(
    credentials_file: str,
    username: Optional[str] = None,
) -> ContrastAuth:
    """
    Create authentication from credentials file.
    
    Args:
        credentials_file: Path to credentials file
        username: Optional username override
        
    Returns:
        ContrastAuth instance
        
    Raises:
        FileNotFoundError: If credentials file doesn't exist
        ValueError: If credentials file is malformed
    """
    import os
    
    if not os.path.exists(credentials_file):
        raise FileNotFoundError(f"Credentials file not found: {credentials_file}")
    
    config = {}
    with open(credentials_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
    
    api_key = config.get('api_key')
    service_key = config.get('service_key')
    file_username = config.get('username')
    
    if not api_key or not service_key:
        raise ValueError("Credentials file must contain api_key and service_key")
    
    return ContrastAuth(
        api_key=api_key,
        service_key=service_key,
        username=username or file_username,
    )


def create_auth_from_fetch_creds(interactive: bool = True) -> Tuple[ContrastAuth, Dict[str, str]]:
    """Create ContrastAuth using the fetch_creds.py system.
    
    This function integrates with the existing CSR-Helpful-Scripts credential system.
    It will read from .creds file and optionally prompt for missing values.
    
    Args:
        interactive: If True, prompts user for missing credentials.
                    If False, only uses .creds file values.
        
    Returns:
        Tuple of (ContrastAuth instance, credential_dict)
        credential_dict contains: contrast_url, org_id, username, api_key, service_key, app_id
        
    Raises:
        ImportError: If fetch_creds module is not available
        ValueError: If required credentials are missing
    """
    if get_credentials is None or read_creds_file is None:
        raise ImportError(
            "fetch_creds module not available. "
            "Make sure fetch_creds.py is in the parent directory."
        )
    
    if interactive:
        # Use the interactive credential collection
        creds = get_credentials()
    else:
        # Only use .creds file, no prompting
        creds_dict = read_creds_file()
        if not creds_dict:
            raise ValueError("No .creds file found and interactive=False")
            
        required_keys = ['API_KEY', 'SERVICE_KEY', 'USERNAME', 'CONTRAST_URL', 'ORG_ID']
        missing_keys = [k for k in required_keys if not creds_dict.get(k)]
        if missing_keys:
            raise ValueError(f"Missing required credentials in .creds file: {missing_keys}")
        
        # Convert to the format expected by the rest of the function
        creds = {
            'contrast_url': creds_dict['CONTRAST_URL'],
            'org_id': creds_dict['ORG_ID'],
            'username': creds_dict['USERNAME'],
            'api_key': creds_dict['API_KEY'],
            'service_key': creds_dict['SERVICE_KEY'],
            'app_id': creds_dict.get('APP_ID', '')
        }
    
    # Create the ContrastAuth instance
    auth = ContrastAuth(
        api_key=creds['api_key'],
        service_key=creds['service_key'],
        username=creds['username']
    )
    
    # Return both auth and full credential info
    credential_info = {
        'contrast_url': creds['contrast_url'],
        'org_id': creds['org_id'],
        'username': creds['username'],
        'api_key': creds['api_key'],
        'service_key': creds['service_key'],
        'app_id': creds.get('app_id', '')
    }
    
    return auth, credential_info


def create_auth_from_creds_file(creds_filename: str = ".creds") -> Tuple[ContrastAuth, Dict[str, str]]:
    """Create ContrastAuth from .creds file (non-interactive).
    
    Args:
        creds_filename: Name of the .creds file (default: ".creds")
        
    Returns:
        Tuple of (ContrastAuth instance, credential_dict)
        
    Raises:
        ImportError: If fetch_creds module is not available
        ValueError: If required credentials are missing
        FileNotFoundError: If .creds file is not found
    """
    if read_creds_file is None:
        raise ImportError(
            "fetch_creds module not available. "
            "Make sure fetch_creds.py is in the parent directory."
        )
    
    creds_dict = read_creds_file(creds_filename)
    if not creds_dict:
        raise FileNotFoundError(f"No {creds_filename} file found")
        
    required_keys = ['API_KEY', 'SERVICE_KEY', 'USERNAME', 'CONTRAST_URL', 'ORG_ID']
    missing_keys = [k for k in required_keys if not creds_dict.get(k)]
    if missing_keys:
        raise ValueError(f"Missing required credentials in {creds_filename} file: {missing_keys}")
    
    # Create the ContrastAuth instance
    auth = ContrastAuth(
        api_key=creds_dict['API_KEY'],
        service_key=creds_dict['SERVICE_KEY'],
        username=creds_dict['USERNAME']
    )
    
    # Return both auth and full credential info
    credential_info = {
        'contrast_url': creds_dict['CONTRAST_URL'],
        'org_id': creds_dict['ORG_ID'],
        'username': creds_dict['USERNAME'],
        'api_key': creds_dict['API_KEY'],
        'service_key': creds_dict['SERVICE_KEY'],
        'app_id': creds_dict.get('APP_ID', '')
    }
    
    return auth, credential_info