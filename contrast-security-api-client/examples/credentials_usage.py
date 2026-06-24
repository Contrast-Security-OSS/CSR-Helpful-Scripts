"""
Example demonstrating credentials file usage and the fetch_creds system.
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
from contrast_security.auth import create_auth_from_file
from contrast_security.exceptions import ContrastAPIError

def create_credentials_file_example():
    """Create an example credentials file."""
    
    example_content = """# Contrast Security Credentials
# Lines starting with # are comments

api_key=your-api-key-here
service_key=your-service-key-here

# Optional: specify organization ID here
# organization_id=your-org-id-here

# Optional: specify base URL (defaults to https://app.contrastsecurity.com)
# base_url=https://app.contrastsecurity.com
"""
    
    with open('contrast_credentials.example', 'w') as f:
        f.write(example_content)
    
    print("Created example credentials file: contrast_credentials.example")
    print("Copy this to contrast_credentials.txt and update with your actual credentials")

def main():
    """Main example function demonstrating credentials file usage and fetch_creds system."""
    
    # Get credentials using the interactive fetch_creds system
    print("=== Contrast Security API Client - Credentials Usage Demo ===")
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
        
        print(f"✅ Credentials collected successfully!")
        print(f"Username: {username}")
        print(f"Organization ID: {org_id}")
        print(f"Contrast URL: {contrast_url}")
        print(f"API Key: {api_key[:10]}... (truncated)")
        print(f"Service Key: {service_key[:10]}... (truncated)")
        print()
        
        # Create example credentials file for reference
        create_credentials_file_example()
        
        # Option 1: Use credentials from fetch_creds
        print("=== Using credentials from fetch_creds ===")
        
        client = ContrastAPI(
            base_url=contrast_url,
            api_key=api_key,
            service_key=service_key,
            username=username,
            organization_id=org_id
        )
        
        # Test the connection
        orgs_response = client.organizations.list()
        if orgs_response.status_code == 200:
            print("✅ Successfully connected using fetch_creds credentials")
            orgs_data = orgs_response.json()
            print(f"Found {len(orgs_data.get('organizations', []))} organizations")
        
    except Exception as e:
        print(f"❌ Failed to get credentials: {e}")
        # Make sure we change back to original directory even on error
        try:
            os.chdir(original_cwd)
        except:
            pass
        return
    
    try:
        # Option 1: Use credentials file with ContrastAPI
        print("\n=== Using credentials file with ContrastAPI ===")
        
        # This will look for contrast_credentials.txt in the current directory
        client = ContrastAPI(
            base_url="https://app.contrastsecurity.com",
            credentials_file="contrast_credentials.txt",  # Update this path
            organization_id="your-org-id-here"  # Can also be in the credentials file
        )
        
        # Test the connection
        orgs_response = client.organizations.list()
        if orgs_response.status_code == 200:
            print("✅ Successfully connected using credentials file")
            orgs_data = orgs_response.json()
            print(f"Found {len(orgs_data.get('organizations', []))} organizations")
        
        # Option 2: Show how to use traditional credentials file (for comparison)
        print("\n=== Traditional credentials file methods (for comparison) ===")
        
        # This will use the example file we created
        credential_locations = [
            "contrast_credentials.example",     # Example file
            "contrast_credentials.txt",         # Current directory
            "~/.contrast/credentials",          # Home directory
            "/etc/contrast/credentials",        # System directory
            "./config/contrast.conf"            # Config directory
        ]
        
        for location in credential_locations:
            try:
                print(f"Trying credentials file: {location}")
                if os.path.exists(location):
                    auth = create_auth_from_file(location)
                    print(f"✅ Successfully loaded from: {location}")
                    break
                else:
                    print(f"❌ File not found: {location}")
            except Exception as e:
                print(f"❌ Error loading {location}: {e}")
    
    except FileNotFoundError:
        print("❌ Credentials file not found")
        print("Please create a credentials file with your actual Contrast Security credentials")
        print("Example file created: contrast_credentials.example")
    
    except ContrastAPIError as e:
        print(f"❌ API Error: {e}")
        print("This might be due to invalid credentials")
    
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def validate_credentials_file(file_path):
    """Validate a credentials file format."""
    
    print(f"\n=== Validating credentials file: {file_path} ===")
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        required_keys = ['api_key', 'service_key']
        found_keys = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Check for key=value format
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key in required_keys:
                    found_keys.append(key)
                    if not value or value == 'your-api-key-here' or value == 'your-service-key-here':
                        print(f"⚠️  Line {line_num}: {key} appears to have placeholder value")
                    else:
                        print(f"✅ Line {line_num}: {key} looks valid")
                else:
                    print(f"ℹ️  Line {line_num}: Optional parameter {key}")
            else:
                print(f"⚠️  Line {line_num}: Invalid format (expected key=value): {line}")
        
        # Check for missing required keys
        missing_keys = set(required_keys) - set(found_keys)
        if missing_keys:
            print(f"❌ Missing required keys: {', '.join(missing_keys)}")
        else:
            print("✅ All required keys found")
    
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
    except Exception as e:
        print(f"❌ Error validating file: {e}")

if __name__ == "__main__":
    main()
    
    # Validate the example file we created
    validate_credentials_file("contrast_credentials.example")