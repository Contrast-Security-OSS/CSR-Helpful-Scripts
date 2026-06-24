"""
Get applications using Contrast Security API client.
Mimics the pattern of get-licensed-apps.py but uses the API client.
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
    """Get all applications from Contrast Security."""
    
    print("=== Get Applications ===")
    
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
        
        # Get all applications
        print("Fetching applications...")
        response = client.applications.list()
        
        if response.status_code == 200:
            data = response.json()
            
            # Save to JSON file
            with open("applications_output.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Applications response saved to applications_output.json")
            
            # Display summary
            applications = data.get('applications', [])
            print(f"\\nTotal Applications: {len(applications)}")
            
            if applications:
                print("\\nApplications found:")
                for app in applications:
                    app_name = app.get('name', 'N/A')
                    app_id = app.get('app_id', 'N/A')
                    language = app.get('language', 'N/A')
                    environment = app.get('environment', 'N/A')
                    print(f"  - {app_name} (ID: {app_id}, Language: {language}, Environment: {environment})")
                
                # Group by language
                languages = {}
                for app in applications:
                    lang = app.get('language', 'Unknown')
                    if lang not in languages:
                        languages[lang] = []
                    languages[lang].append(app)
                
                print(f"\\nApplications by language:")
                for lang, apps in languages.items():
                    print(f"  {lang}: {len(apps)} applications")
            else:
                print("No applications found.")
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