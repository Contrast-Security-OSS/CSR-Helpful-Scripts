"""
Get libraries using Contrast Security API client.
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
    """Get all libraries from Contrast Security."""
    
    print("=== Get Libraries ===")
    
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
        
        # Get all libraries
        print("Fetching libraries...")
        response = client.libraries.list(limit=100)  # Get up to 100 libraries
        
        if response.status_code == 200:
            data = response.json()
            
            # Save to JSON file
            with open("libraries_output.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Libraries response saved to libraries_output.json")
            
            # Display summary
            libraries = data.get('libraries', [])
            total_count = data.get('count', len(libraries))
            
            print(f"\\nTotal Libraries: {total_count}")
            print(f"Retrieved: {len(libraries)} libraries")
            
            if libraries:
                print("\\nLibraries found:")
                
                # Track statistics
                by_language = {}
                vulnerable_libraries = []
                outdated_libraries = []
                
                for lib in libraries:
                    lib_name = lib.get('file_name', lib.get('name', 'N/A'))
                    lib_version = lib.get('version', 'N/A')
                    language = lib.get('language', 'Unknown')
                    vuln_count = lib.get('total_vulnerabilities', 0)
                    outdated = lib.get('outdated', False)
                    
                    # Count by language
                    if language not in by_language:
                        by_language[language] = []
                    by_language[language].append(lib)
                    
                    # Track vulnerable libraries
                    if vuln_count > 0:
                        vulnerable_libraries.append({
                            'name': lib_name,
                            'version': lib_version,
                            'language': language,
                            'vulnerabilities': vuln_count
                        })
                    
                    # Track outdated libraries
                    if outdated:
                        outdated_libraries.append({
                            'name': lib_name,
                            'version': lib_version,
                            'language': language
                        })
                
                # Display first 10 libraries
                print(f"\\nFirst {min(10, len(libraries))} libraries:")
                for i, lib in enumerate(libraries[:10], 1):
                    lib_name = lib.get('file_name', lib.get('name', 'N/A'))
                    lib_version = lib.get('version', 'N/A')
                    language = lib.get('language', 'N/A')
                    vuln_count = lib.get('total_vulnerabilities', 0)
                    outdated = lib.get('outdated', False)
                    
                    status_indicators = []
                    if vuln_count > 0:
                        status_indicators.append(f"⚠️ {vuln_count} vulns")
                    if outdated:
                        status_indicators.append("📅 outdated")
                    if not status_indicators:
                        status_indicators.append("✅ clean")
                    
                    status = " ".join(status_indicators)
                    print(f"  {i}. {lib_name} v{lib_version} ({language}) - {status}")
                
                # Display summaries
                print(f"\\nLibraries by language:")
                for language, libs in sorted(by_language.items()):
                    print(f"  {language}: {len(libs)} libraries")
                
                if vulnerable_libraries:
                    print(f"\\nTop 10 Most Vulnerable Libraries:")
                    vulnerable_libraries.sort(key=lambda x: x['vulnerabilities'], reverse=True)
                    for i, lib in enumerate(vulnerable_libraries[:10], 1):
                        print(f"  {i}. {lib['name']} v{lib['version']} ({lib['language']}) - {lib['vulnerabilities']} vulnerabilities")
                
                if outdated_libraries:
                    print(f"\\nOutdated Libraries ({len(outdated_libraries)} total):")
                    for i, lib in enumerate(outdated_libraries[:10], 1):
                        print(f"  {i}. {lib['name']} v{lib['version']} ({lib['language']})")
                    if len(outdated_libraries) > 10:
                        print(f"  ... and {len(outdated_libraries) - 10} more")
                
                print(f"\\nSecurity Summary:")
                print(f"  Libraries with vulnerabilities: {len(vulnerable_libraries)}")
                print(f"  Outdated libraries: {len(outdated_libraries)}")
                print(f"  Clean libraries: {len(libraries) - len(vulnerable_libraries)}")
                
                if total_count > len(libraries):
                    print(f"\\n(Note: Only showing first {len(libraries)} of {total_count} total libraries)")
            else:
                print("No libraries found.")
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