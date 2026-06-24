"""
Basic usage example for the Contrast Security API client.
"""

import sys
import os

# Add the directory containing this script and its parent to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
grandparent_dir = os.path.dirname(parent_dir)
sys.path.insert(0, script_dir)
sys.path.insert(0, parent_dir) 
sys.path.insert(0, grandparent_dir)

try:
    from fetch_creds import get_credentials
except ImportError:
    print("Error: Cannot find fetch_creds module. Make sure fetch_creds.py is in the parent directory.")
    sys.exit(1)

from contrast_security import ContrastAPI
from contrast_security.exceptions import ContrastAPIError

def main():
    """Main example function."""
    
    # Get credentials using the interactive fetch_creds system
    print("=== Contrast Security API Client - Basic Usage ===")
    print("This example will prompt you for your Contrast Security credentials.")
    print()
    
    try:
        # Change to the CSR-Helpful-Scripts root directory where .creds file should be
        original_cwd = os.getcwd()
        csr_root_dir = os.path.join(grandparent_dir)
        os.chdir(csr_root_dir)
        
        # Get credentials interactively
        creds = get_credentials()
        contrast_url = creds["contrast_url"]
        org_id = creds["org_id"]
        username = creds["username"]
        api_key = creds["api_key"]
        service_key = creds["service_key"]
        
        # Change back to original directory
        os.chdir(original_cwd)
        
        # Initialize client with credentials
        client = ContrastAPI(
            base_url=contrast_url,
            api_key=api_key,
            service_key=service_key,
            username=username,
            organization_id=org_id
        )
        
        print(f"✅ Connected to Contrast Security as: {username}")
        print(f"Organization ID: {org_id}")
        print(f"Contrast URL: {contrast_url}")
        print()
    
    except Exception as e:
        print(f"❌ Failed to get credentials: {e}")
        # Make sure we change back to original directory even on error
        try:
            os.chdir(original_cwd)
        except:
            pass
        return
    
    try:
        # Get all organizations (to find your org ID)
        print("Getting organizations...")
        orgs_response = client.organizations.list()
        print(f"Found {len(orgs_response.json().get('organizations', []))} organizations")
        
        # Get all applications
        print("\nGetting applications...")
        apps_response = client.applications.list(limit=10)
        apps_data = apps_response.json()
        
        print(f"Found {apps_data.get('count', 0)} total applications")
        
        # Display application details
        for app in apps_data.get('applications', []):
            print(f"  - {app.get('name')} ({app.get('language')}) - {app.get('app_id')}")
        
        # Get vulnerabilities if we have applications
        if apps_data.get('applications'):
            app_id = apps_data['applications'][0]['app_id']
            app_name = apps_data['applications'][0]['name']
            
            print(f"\nGetting vulnerabilities for application: {app_name}")
            vulns_response = client.vulnerabilities.list_by_application(app_id, limit=5)
            vulns_data = vulns_response.json()
            
            print(f"Found {vulns_data.get('count', 0)} vulnerabilities")
            
            # Display vulnerability details
            for vuln in vulns_data.get('traces', []):
                print(f"  - {vuln.get('title')} ({vuln.get('severity')}) - {vuln.get('status')}")
        
        # Get servers
        print("\nGetting servers...")
        servers_response = client.servers.list(limit=5)
        servers_data = servers_response.json()
        
        print(f"Found {servers_data.get('count', 0)} servers")
        
        # Display server details
        for server in servers_data.get('servers', []):
            print(f"  - {server.get('name')} ({server.get('type')}) - {server.get('environment')}")
    
    except ContrastAPIError as e:
        print(f"API Error: {e}")
        if hasattr(e, 'status_code'):
            print(f"Status Code: {e.status_code}")
        if hasattr(e, 'response_data'):
            print(f"Response: {e.response_data}")
    
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()