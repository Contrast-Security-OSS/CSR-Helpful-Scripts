"""
Get users using Contrast Security API client.
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
    """Get all users from Contrast Security."""
    
    print("=== Get Users ===")
    
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
        
        # Get all users
        print("Fetching users...")
        response = client.users.list()
        
        if response.status_code == 200:
            data = response.json()
            
            # Save to JSON file
            with open("users_output.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Users response saved to users_output.json")
            
            # Display summary
            users = data.get('users', [])
            print(f"\\nTotal Users: {len(users)}")
            
            if users:
                print("\\nUsers found:")
                
                # Track statistics
                by_role = {}
                active_users = 0
                
                for user in users:
                    user_name = user.get('name', 'N/A')
                    user_email = user.get('email', 'N/A')
                    user_uuid = user.get('user_uuid', 'N/A')
                    role = user.get('role', 'N/A')
                    last_login = user.get('last_login_date', 'Never')
                    enabled = user.get('enabled', False)
                    
                    print(f"  - {user_name} ({user_email})")
                    print(f"    UUID: {user_uuid}")
                    print(f"    Role: {role}")
                    print(f"    Last Login: {last_login}")
                    print(f"    Status: {'✅ Active' if enabled else '❌ Inactive'}")
                    
                    # Highlight if this is the current user
                    if user_email.lower() == username.lower():
                        print(f"    👤 This is your account")
                    
                    print()
                    
                    # Track role stats
                    if role not in by_role:
                        by_role[role] = 0
                    by_role[role] += 1
                    
                    # Track active users
                    if enabled:
                        active_users += 1
                
                # Display summaries
                print(f"\\nUsers by role:")
                for role, count in sorted(by_role.items()):
                    print(f"  {role}: {count}")
                
                print(f"\\nUser Status Summary:")
                print(f"  Active users: {active_users}")
                print(f"  Inactive users: {len(users) - active_users}")
            else:
                print("No users found.")
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