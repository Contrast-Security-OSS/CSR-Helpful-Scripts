"""
Example using fetch_creds.py system - Non-interactive mode.
"""

from contrast_security import ContrastAPI
from contrast_security.exceptions import ContrastAPIError

def main():
    """Main example function using fetch_creds system (non-interactive)."""
    
    try:
        # Option 1: Non-interactive mode (only uses .creds file)
        print("=== Using ContrastAPI.from_fetch_creds() - Non-interactive ===")
        print("This will only read from .creds file, no prompting...")
        
        client = ContrastAPI.from_fetch_creds(interactive=False)
        
        # Display credential information that was loaded
        cred_info = client.credential_info
        print(f"✅ Loaded credentials for: {cred_info.get('username', 'Unknown')}")
        print(f"Organization ID: {cred_info.get('org_id', 'Not set')}")
        print(f"Contrast URL: {cred_info.get('contrast_url', 'Not set')}")
        
        # Option 2: Manual initialization with fetch_creds
        print("\n=== Using manual initialization with fetch_creds ===")
        
        client2 = ContrastAPI(use_fetch_creds=True, interactive_creds=False)
        
        # Test the connection
        print("\nTesting API connection...")
        orgs_response = client.organizations.list()
        orgs_data = orgs_response.json()
        
        print(f"✅ Successfully connected!")
        print(f"Found {len(orgs_data.get('organizations', []))} organizations")
        
        # Show organization details
        for org in orgs_data.get('organizations', []):
            org_name = org.get('name', 'Unknown')
            org_id = org.get('organization_uuid', 'Unknown')
            print(f"  - {org_name} ({org_id})")
        
        # Get application summary
        print("\n=== Application Summary ===")
        apps_response = client.applications.list()
        apps_data = apps_response.json()
        
        print(f"Total applications: {apps_data.get('count', 0)}")
        
        # Group applications by language
        app_languages = {}
        for app in apps_data.get('applications', []):
            lang = app.get('language', 'Unknown')
            if lang not in app_languages:
                app_languages[lang] = []
            app_languages[lang].append(app)
        
        print(f"\nApplications by language:")
        for lang, apps in app_languages.items():
            print(f"  {lang}: {len(apps)} applications")
        
        # Get vulnerability summary
        print("\n=== Vulnerability Summary ===")
        vulns_response = client.vulnerabilities.list(limit=1)  # Just to get count
        vulns_data = vulns_response.json()
        
        total_vulns = vulns_data.get('count', 0)
        print(f"Total vulnerabilities: {total_vulns}")
        
        # Get vulnerability breakdown by severity
        if total_vulns > 0:
            for severity in ["Critical", "High", "Medium", "Low"]:
                severity_response = client.vulnerabilities.list(
                    severity=[severity], 
                    limit=1
                )
                severity_data = severity_response.json()
                severity_count = severity_data.get('count', 0)
                
                if severity_count > 0:
                    print(f"  {severity}: {severity_count} vulnerabilities")
        
        # Get server summary
        print("\n=== Server Summary ===")
        servers_response = client.servers.list(limit=1)  # Just to get count
        servers_data = servers_response.json()
        
        print(f"Total servers: {servers_data.get('count', 0)}")
        
    except ContrastAPIError as e:
        print(f"❌ API Error: {e}")
        if hasattr(e, 'status_code'):
            print(f"Status Code: {e.status_code}")
        
        # Provide specific guidance based on error type
        if e.status_code == 401:
            print("\n🔑 Authentication Error - Check your credentials:")
            print("   - API_KEY: Ensure it's valid and not expired")
            print("   - SERVICE_KEY: Verify the service key is correct")
            print("   - USERNAME: Make sure the username is correct")
        elif e.status_code == 403:
            print("\n🚫 Authorization Error - Check your permissions:")
            print("   - ORG_ID: Verify the organization ID is correct")
            print("   - Ensure your user has access to the organization")
        elif e.status_code == 404:
            print("\n📍 Not Found Error - Check your configuration:")
            print("   - CONTRAST_URL: Verify the Contrast URL is correct")
            print("   - Ensure the API endpoints are available")
        
    except Exception as e:
        print(f"❌ Setup error: {e}")
        print("\n🔧 Troubleshooting steps:")
        print("1. Ensure .creds file exists in the parent directory")
        print("2. Copy and rename template.creds to .creds:")
        print("   cp ../template.creds ../.creds")
        print("3. Edit .creds file with your actual Contrast Security credentials")
        print("4. Required fields in .creds:")
        print("   - CONTRAST_URL=https://your-instance.contrastsecurity.com")
        print("   - ORG_ID=your-organization-uuid")
        print("   - USERNAME=your-username")
        print("   - API_KEY=your-api-key")
        print("   - SERVICE_KEY=your-service-key")

if __name__ == "__main__":
    main()