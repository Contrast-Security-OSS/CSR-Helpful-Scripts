"""
Example demonstrating application and library management.
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
    """Main example function for application and library management."""
    
    # Get credentials using the interactive fetch_creds system
    print("=== Contrast Security API Client - Application Management ===")
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
        # Get applications with detailed information
        print("Getting applications with details...")
        apps_response = client.applications.list(
            expand=["scores", "technologies", "libraries"],
            limit=10
        )
        apps_data = apps_response.json()
        
        print(f"Found {apps_data.get('count', 0)} applications")
        
        for app in apps_data.get('applications', []):
            app_name = app.get('name')
            app_id = app.get('app_id')
            language = app.get('language')
            
            print(f"\n=== Application: {app_name} ===")
            print(f"ID: {app_id}")
            print(f"Language: {language}")
            print(f"Path: {app.get('path', 'N/A')}")
            print(f"Environment: {app.get('environment', 'N/A')}")
            
            # Get application scores if available
            scores = app.get('scores', {})
            if scores:
                print(f"Security Score: {scores.get('security', 'N/A')}")
                print(f"Library Score: {scores.get('library', 'N/A')}")
                print(f"Custom Code Score: {scores.get('custom', 'N/A')}")
            
            # Get libraries for this application
            print("\nLibraries:")
            libs_response = client.libraries.list_by_application(app_id, limit=10)
            libs_data = libs_response.json()
            
            for lib in libs_data.get('libraries', []):
                lib_name = lib.get('file_name', lib.get('name', 'Unknown'))
                lib_version = lib.get('version', 'Unknown')
                lib_lang = lib.get('language', language)
                
                # Check if library has vulnerabilities
                vuln_count = lib.get('total_vulnerabilities', 0)
                status_indicator = "⚠️" if vuln_count > 0 else "✅"
                
                print(f"  {status_indicator} {lib_name} v{lib_version} ({lib_lang})")
                if vuln_count > 0:
                    print(f"    └── {vuln_count} vulnerabilities")
            
            # Get application metadata/tags
            metadata_response = client.metadata.get_application_metadata(app_id)
            if metadata_response.status_code == 200:
                metadata = metadata_response.json()
                tags = metadata.get('metadata', {})
                if tags:
                    print(f"\nTags/Metadata:")
                    for key, value in tags.items():
                        print(f"  {key}: {value}")
            
            break  # Just show first app for demo
        
        # Example: Add tags to an application
        if apps_data.get('applications'):
            app = apps_data['applications'][0]
            app_id = app.get('app_id')
            app_name = app.get('name')
            
            print(f"\n=== Adding tags to application: {app_name} ===")
            
            # Add some example tags
            tags_to_add = {
                "Environment": "Production",
                "Team": "Security Team",
                "Business_Unit": "Engineering",
                "Criticality": "High"
            }
            
            for key, value in tags_to_add.items():
                try:
                    tag_response = client.metadata.add_application_metadata(
                        app_id, 
                        key, 
                        value
                    )
                    if tag_response.status_code == 200:
                        print(f"  ✅ Added tag: {key} = {value}")
                    else:
                        print(f"  ❌ Failed to add tag: {key} = {value}")
                except ContrastAPIError as e:
                    print(f"  ❌ Error adding tag {key}: {e}")
        
        # Get organization libraries summary
        print("\n=== Organization Library Summary ===")
        org_libs_response = client.libraries.list(
            sort="score",
            limit=20
        )
        org_libs_data = org_libs_response.json()
        
        print(f"Total libraries in organization: {org_libs_data.get('count', 0)}")
        
        # Group libraries by language
        lib_languages = {}
        vulnerable_libs = []
        
        for lib in org_libs_data.get('libraries', []):
            lang = lib.get('language', 'Unknown')
            if lang not in lib_languages:
                lib_languages[lang] = []
            lib_languages[lang].append(lib)
            
            # Track vulnerable libraries
            if lib.get('total_vulnerabilities', 0) > 0:
                vulnerable_libs.append(lib)
        
        print(f"\nLibraries by language:")
        for lang, libs in lib_languages.items():
            print(f"  {lang}: {len(libs)} libraries")
        
        print(f"\nVulnerable libraries: {len(vulnerable_libs)}")
        
        # Show top 5 most vulnerable libraries
        if vulnerable_libs:
            vulnerable_libs.sort(
                key=lambda x: x.get('total_vulnerabilities', 0), 
                reverse=True
            )
            
            print(f"\nTop vulnerable libraries:")
            for lib in vulnerable_libs[:5]:
                lib_name = lib.get('file_name', lib.get('name', 'Unknown'))
                vuln_count = lib.get('total_vulnerabilities', 0)
                print(f"  📚 {lib_name}: {vuln_count} vulnerabilities")
    
    except ContrastAPIError as e:
        print(f"API Error: {e}")
        if hasattr(e, 'status_code'):
            print(f"Status Code: {e.status_code}")
    
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()