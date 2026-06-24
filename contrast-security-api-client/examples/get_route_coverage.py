"""
Get route coverage using Contrast Security API client.
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
    """Get route coverage data from Contrast Security."""
    
    print("=== Get Route Coverage ===")
    
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
        
        # First get applications to analyze route coverage for
        print("Fetching applications...")
        apps_response = client.applications.list()
        
        if apps_response.status_code != 200:
            print(f"Error fetching applications: {apps_response.status_code} - {apps_response.text}")
            return
        
        apps_data = apps_response.json()
        applications = apps_data.get('applications', [])
        
        if not applications:
            print("No applications found.")
            return
        
        print(f"Found {len(applications)} applications")
        
        # Get route coverage for each application
        all_coverage_data = {}
        coverage_summary = {
            'total_routes': 0,
            'exercised_routes': 0,
            'discovered_routes': 0,
            'coverage_by_app': {}
        }
        
        for app in applications:
            app_id = app.get('app_id')
            app_name = app.get('name')
            
            if not app_id:
                continue
            
            print(f"\\nFetching route coverage for: {app_name}")
            
            try:
                # Get route coverage for this application
                coverage_response = client.applications.get_route_coverage(app_id)
                
                if coverage_response.status_code == 200:
                    coverage_data = coverage_response.json()
                    routes = coverage_data.get('routes', [])
                    
                    # Analyze routes
                    exercised = [r for r in routes if r.get('exercised') == True]
                    discovered = [r for r in routes if r.get('exercised') == False]
                    
                    # Store data
                    all_coverage_data[app_name] = {
                        'app_id': app_id,
                        'routes': routes,
                        'exercised_count': len(exercised),
                        'discovered_count': len(discovered),
                        'total_count': len(routes),
                        'coverage_percentage': (len(exercised) / len(routes) * 100) if routes else 0
                    }
                    
                    # Update summary
                    coverage_summary['total_routes'] += len(routes)
                    coverage_summary['exercised_routes'] += len(exercised)
                    coverage_summary['discovered_routes'] += len(discovered)
                    coverage_summary['coverage_by_app'][app_name] = {
                        'exercised': len(exercised),
                        'discovered': len(discovered),
                        'total': len(routes),
                        'percentage': (len(exercised) / len(routes) * 100) if routes else 0
                    }
                    
                    print(f"  ✅ Total routes: {len(routes)}")
                    print(f"  🟢 Exercised: {len(exercised)}")
                    print(f"  🔵 Discovered only: {len(discovered)}")
                    print(f"  📊 Coverage: {(len(exercised) / len(routes) * 100):.1f}%" if routes else "  📊 Coverage: N/A")
                    
                else:
                    print(f"  ❌ Error: {coverage_response.status_code} - {coverage_response.text}")
                    all_coverage_data[app_name] = {'error': f"{coverage_response.status_code} - {coverage_response.text}"}
                    
            except Exception as e:
                print(f"  ❌ Error getting coverage for {app_name}: {e}")
                all_coverage_data[app_name] = {'error': str(e)}
        
        # Save all data to JSON
        output_data = {
            'summary': coverage_summary,
            'applications': all_coverage_data
        }
        
        with open("route_coverage_output.json", "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\\nRoute coverage data saved to route_coverage_output.json")
        
        # Display overall summary
        print(f"\\n=== Overall Route Coverage Summary ===")
        total = coverage_summary['total_routes']
        exercised = coverage_summary['exercised_routes']
        discovered = coverage_summary['discovered_routes']
        
        if total > 0:
            overall_percentage = (exercised / total) * 100
            print(f"Total routes across all applications: {total}")
            print(f"Exercised routes: {exercised} ({overall_percentage:.1f}%)")
            print(f"Discovered only routes: {discovered} ({(discovered/total)*100:.1f}%)")
            
            print(f"\\n=== Top Applications by Route Coverage ===")
            sorted_apps = sorted(
                coverage_summary['coverage_by_app'].items(),
                key=lambda x: x[1]['percentage'],
                reverse=True
            )
            
            for app_name, data in sorted_apps[:10]:  # Top 10
                print(f"  {app_name}: {data['exercised']}/{data['total']} routes ({data['percentage']:.1f}%)")
            
            print(f"\\n=== Applications with Poor Coverage (< 50%) ===")
            poor_coverage = [
                (name, data) for name, data in coverage_summary['coverage_by_app'].items()
                if data['percentage'] < 50 and data['total'] > 0
            ]
            
            if poor_coverage:
                for app_name, data in sorted(poor_coverage, key=lambda x: x[1]['percentage']):
                    print(f"  ⚠️  {app_name}: {data['exercised']}/{data['total']} routes ({data['percentage']:.1f}%)")
            else:
                print("  🎉 All applications have good coverage (≥50%)!")
        else:
            print("No routes found across any applications.")
    
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