"""
Get organizations using Contrast Security API client.
"""

import sys
import os
import json

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
    """Get all organizations from Contrast Security."""
    
    print("=== Get Organizations ===")
    
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
        print()
        
        # Get all organizations
        print("Fetching organizations...")
        response = client.organizations.list()
        
        if response.status_code == 200:
            data = response.json()
            
            # Save to JSON file
            with open("organizations_output.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Organizations response saved to organizations_output.json")
            
            # Display summary
            organizations = data.get('organizations', [])
            print(f"\\nTotal Organizations: {len(organizations)}")
            
            if organizations:
                print("\\nOrganizations found:")
                
                for org in organizations:
                    org_name = org.get('name', 'N/A')
                    org_uuid = org.get('organization_uuid', 'N/A')
                    org_shortname = org.get('shortname', 'N/A')
                    timezone = org.get('timezone', 'N/A')
                    date_format = org.get('date_format', 'N/A')
                    time_format = org.get('time_format', 'N/A')
                    
                    print(f"  - {org_name}")
                    print(f"    UUID: {org_uuid}")
                    print(f"    Short Name: {org_shortname}")
                    print(f"    Timezone: {timezone}")
                    print(f"    Date Format: {date_format}")
                    print(f"    Time Format: {time_format}")
                    
                    # Highlight if this is the current organization
                    if org_uuid == org_id:
                        print(f"    ✅ This is your current organization")
                    
                    print()
            else:
                print("No organizations found.")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    
    except ContrastAPIError as e:
        print(f"❌ API Error: {e}")
        if hasattr(e, 'status_code'):
            print(f"Status Code: {e.status_code}")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        # Make sure we change back to original directory even on error
        try:
            os.chdir(original_cwd)
        except:
            pass

if __name__ == "__main__":
    main()