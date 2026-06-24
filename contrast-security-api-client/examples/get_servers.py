"""
Get servers using Contrast Security API client.
Mimics the pattern of get-licensed-servers.py but uses the API client.
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
    """Get all servers from Contrast Security."""
    
    print("=== Get Servers ===")
    
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
        
        # Get all servers with expanded information
        print("Fetching servers...")
        response = client.servers.list(expand=["apps", "vulns"])
        
        if response.status_code == 200:
            data = response.json()
            
            # Save to JSON file
            with open("servers_output.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Servers response saved to servers_output.json")
            
            # Display summary
            servers = data.get('servers', [])
            print(f"\\nTotal Servers: {len(servers)}")
            
            if servers:
                print("\\nServers found:")
                
                # Track statistics
                by_environment = {}
                by_container = {}
                protect_enabled = 0
                assess_enabled = 0
                
                for server in servers:
                    server_name = server.get('name', 'N/A')
                    server_id = server.get('id', 'N/A') 
                    server_type = server.get('type', 'N/A')
                    environment = server.get('environment', 'N/A')
                    container = server.get('container', 'N/A')
                    protect_license = server.get('defend', False)
                    assess_license = server.get('assess', False)
                    
                    print(f"  - {server_name} (ID: {server_id})")
                    print(f"    Type: {server_type}, Environment: {environment}")
                    print(f"    Container: {container}")
                    print(f"    Protect License: {'✅' if protect_license else '❌'}")
                    print(f"    Assess License: {'✅' if assess_license else '❌'}")
                    print()
                    
                    # Track environment stats
                    if environment not in by_environment:
                        by_environment[environment] = 0
                    by_environment[environment] += 1
                    
                    # Track container stats
                    if container not in by_container:
                        by_container[container] = 0
                    by_container[container] += 1
                    
                    # Track license stats
                    if protect_license:
                        protect_enabled += 1
                    if assess_license:
                        assess_enabled += 1
                
                # Display summaries
                print(f"\\nServers by environment:")
                for env, count in sorted(by_environment.items()):
                    print(f"  {env}: {count}")
                
                print(f"\\nServers by container:")
                for container, count in sorted(by_container.items()):
                    print(f"  {container}: {count}")
                
                print(f"\\nLicense Summary:")
                print(f"  Protect licenses enabled: {protect_enabled}/{len(servers)}")
                print(f"  Assess licenses enabled: {assess_enabled}/{len(servers)}")
            else:
                print("No servers found.")
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