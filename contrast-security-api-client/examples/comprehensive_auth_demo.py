"""
Comprehensive example showing all authentication methods including fetch_creds.
"""

from contrast_security import ContrastAPI
from contrast_security.auth import create_auth_from_fetch_creds, create_auth_from_creds_file
from contrast_security.exceptions import ContrastAPIError

def demo_fetch_creds_interactive():
    """Demonstrate interactive fetch_creds usage."""
    print("=" * 60)
    print("DEMO: Interactive fetch_creds (prompts for missing values)")
    print("=" * 60)
    
    try:
        # This will read .creds file and prompt for any missing values
        client = ContrastAPI.from_fetch_creds(interactive=True)
        
        cred_info = client.credential_info
        print(f"✅ Connected as: {cred_info.get('username')}")
        print(f"Organization: {cred_info.get('org_id')}")
        print(f"URL: {cred_info.get('contrast_url')}")
        
        return client
        
    except Exception as e:
        print(f"❌ Interactive mode failed: {e}")
        return None

def demo_fetch_creds_noninteractive():
    """Demonstrate non-interactive fetch_creds usage."""
    print("=" * 60)
    print("DEMO: Non-interactive fetch_creds (only .creds file)")
    print("=" * 60)
    
    try:
        # This only uses .creds file, no prompting
        client = ContrastAPI.from_fetch_creds(interactive=False)
        
        cred_info = client.credential_info
        print(f"✅ Connected as: {cred_info.get('username')}")
        print(f"Organization: {cred_info.get('org_id')}")
        print(f"URL: {cred_info.get('contrast_url')}")
        
        return client
        
    except Exception as e:
        print(f"❌ Non-interactive mode failed: {e}")
        return None

def demo_manual_fetch_creds():
    """Demonstrate manual use of fetch_creds functions."""
    print("=" * 60)
    print("DEMO: Manual fetch_creds usage")
    print("=" * 60)
    
    try:
        # Method 1: Create auth and credentials separately
        auth, creds = create_auth_from_creds_file(".creds")
        
        # Use the auth object with client
        client = ContrastAPI(
            base_url=creds['contrast_url'],
            organization_id=creds['org_id'],
            auth=auth
        )
        
        print(f"✅ Manual setup successful")
        print(f"Username: {creds['username']}")
        print(f"Organization: {creds['org_id']}")
        
        return client, creds
        
    except Exception as e:
        print(f"❌ Manual setup failed: {e}")
        return None, None

def demo_traditional_methods():
    """Demonstrate traditional authentication methods for comparison."""
    print("=" * 60)
    print("DEMO: Traditional authentication methods")
    print("=" * 60)
    
    try:
        # Method 1: Direct credentials
        print("Method 1: Direct credentials (not recommended for production)")
        client1 = ContrastAPI(
            base_url="https://app.contrastsecurity.com",
            api_key="your-api-key-here",
            service_key="your-service-key-here",
            organization_id="your-org-id-here"
        )
        print("✅ Direct credentials client created")
        
        # Method 2: Credentials file
        print("Method 2: Credentials file")
        client2 = ContrastAPI(
            base_url="https://app.contrastsecurity.com",
            credentials_file="contrast_credentials.txt",
            organization_id="your-org-id-here"
        )
        print("✅ Credentials file client created")
        
        return client1
        
    except Exception as e:
        print(f"❌ Traditional methods demo: {e}")
        return None

def run_api_tests(client):
    """Run some basic API tests with the provided client."""
    if not client:
        print("⚠️ No client available for testing")
        return
    
    print("\\n" + "=" * 60)
    print("API TESTS")
    print("=" * 60)
    
    try:
        # Test organizations
        print("Testing organizations endpoint...")
        orgs_response = client.organizations.list()
        orgs_data = orgs_response.json()
        print(f"✅ Organizations: {len(orgs_data.get('organizations', []))} found")
        
        # Test applications
        print("Testing applications endpoint...")
        apps_response = client.applications.list(limit=3)
        apps_data = apps_response.json()
        print(f"✅ Applications: {apps_data.get('count', 0)} total")
        
        # Show first few applications
        for app in apps_data.get('applications', [])[:3]:
            print(f"   - {app.get('name')} ({app.get('language')})")
        
        # Test vulnerabilities
        print("Testing vulnerabilities endpoint...")
        vulns_response = client.vulnerabilities.list(limit=1)
        vulns_data = vulns_response.json()
        print(f"✅ Vulnerabilities: {vulns_data.get('count', 0)} total")
        
        # Test servers
        print("Testing servers endpoint...")
        servers_response = client.servers.list(limit=1)
        servers_data = servers_response.json()
        print(f"✅ Servers: {servers_data.get('count', 0)} total")
        
        return True
        
    except ContrastAPIError as e:
        print(f"❌ API test failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected test error: {e}")
        return False

def main():
    """Main demonstration function."""
    print("Contrast Security API Client - Authentication Methods Demo")
    print("This demo shows different ways to authenticate with the API.")
    print()
    
    # Try different authentication methods
    successful_client = None
    
    # Try non-interactive fetch_creds first (safest for automation)
    client = demo_fetch_creds_noninteractive()
    if client:
        successful_client = client
    
    # If non-interactive failed, try manual method
    if not successful_client:
        client, creds = demo_manual_fetch_creds()
        if client:
            successful_client = client
    
    # Show traditional methods for comparison
    demo_traditional_methods()
    
    # If we have a working client, run API tests
    if successful_client:
        run_api_tests(successful_client)
    else:
        print("\\n⚠️ No working authentication method found.")
        print("Please ensure you have a properly configured .creds file.")
        print("\\nTo set up .creds file:")
        print("1. Copy template: cp ../template.creds ../.creds")
        print("2. Edit with your credentials: nano ../.creds")
        print("3. Required fields:")
        print("   - CONTRAST_URL=https://your-instance.contrastsecurity.com")
        print("   - ORG_ID=your-organization-uuid")
        print("   - USERNAME=your-username")
        print("   - API_KEY=your-api-key")
        print("   - SERVICE_KEY=your-service-key")

if __name__ == "__main__":
    main()