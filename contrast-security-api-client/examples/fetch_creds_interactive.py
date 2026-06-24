"""
Example using fetch_creds.py system - Interactive mode.
"""

from contrast_security import ContrastAPI
from contrast_security.exceptions import ContrastAPIError

def main():
    """Main example function using fetch_creds system."""
    
    try:
        # Option 1: Use the convenience method (interactive mode)
        print("=== Using ContrastAPI.from_fetch_creds() ===")
        print("This will read from .creds file and prompt for any missing values...")
        
        client = ContrastAPI.from_fetch_creds(interactive=True)
        
        # Display credential information that was loaded
        cred_info = client.credential_info
        print(f"Loaded credentials for: {cred_info.get('username', 'Unknown')}")
        print(f"Organization ID: {cred_info.get('org_id', 'Not set')}")
        print(f"Contrast URL: {cred_info.get('contrast_url', 'Not set')}")
        
        # Test the connection
        print("\nTesting API connection...")
        orgs_response = client.organizations.list()
        orgs_data = orgs_response.json()
        
        print(f"✅ Successfully connected!")
        print(f"Found {len(orgs_data.get('organizations', []))} organizations")
        
        # Get applications
        print("\nGetting applications...")
        apps_response = client.applications.list(limit=5)
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
            vulns_response = client.vulnerabilities.list_by_application(app_id, limit=3)
            vulns_data = vulns_response.json()
            
            print(f"Found {vulns_data.get('count', 0)} vulnerabilities")
            
            # Display vulnerability details
            for vuln in vulns_data.get('traces', []):
                print(f"  - {vuln.get('title')} ({vuln.get('severity')}) - {vuln.get('status')}")
    
    except ContrastAPIError as e:
        print(f"❌ API Error: {e}")
        if hasattr(e, 'status_code'):
            print(f"Status Code: {e.status_code}")
        if hasattr(e, 'response_data'):
            print(f"Response: {e.response_data}")
    
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("\nTroubleshooting tips:")
        print("1. Make sure you have a .creds file in the parent directory")
        print("2. Ensure your .creds file has all required values:")
        print("   - CONTRAST_URL")
        print("   - ORG_ID") 
        print("   - USERNAME")
        print("   - API_KEY")
        print("   - SERVICE_KEY")

if __name__ == "__main__":
    main()