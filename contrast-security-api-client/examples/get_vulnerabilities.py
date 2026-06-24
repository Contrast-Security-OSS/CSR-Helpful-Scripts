"""
Get vulnerabilities using Contrast Security API client.
"""

import sys
import os
import json
import requests
import base64
import datetime

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
    """Get all vulnerabilities from Contrast Security."""
    
    print("=== Get Vulnerabilities ===")
    
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
        
        # First get all applications
        print("Fetching applications...")
        apps_response = client.applications.list()
        
        if apps_response.status_code != 200:
            print(f"❌ Error fetching applications: {apps_response.status_code} - {apps_response.text}")
            return
        
        apps_data = apps_response.json()
        applications = apps_data.get('applications', [])
        print(f"Found {len(applications)} applications")
        
        if not applications:
            print("No applications found - cannot fetch vulnerabilities")
            return
        
        # Get vulnerabilities for each application
        all_vulnerabilities = []
        app_vulnerability_counts = {}
        
        for app in applications:
            app_id = app.get('app_id')
            app_name = app.get('name')
            
            if not app_id:
                continue
                
            print(f"Fetching vulnerabilities for: {app_name}")
            
            try:
                # Use the correct filter endpoint to get ALL vulnerabilities
                print(f"  Making API call to get vulnerabilities for app {app_id}")
                
                # Build the URL manually since the client library might not support the filter endpoint correctly
                filter_url = f"{contrast_url}/api/ng/{org_id}/traces/{app_id}/filter"
                
                # Headers for authentication
                headers = {
                    'API-Key': api_key,
                    'Authorization': f'Basic {base64.b64encode(f"{username}:{service_key}".encode()).decode()}'
                }
                
                # Parameters to get all vulnerabilities (no status filter)
                params = {
                    'expand': 'request,application,events,notes,card',  # Get all detailed information
                    'limit': 10000  # High limit to get all vulnerabilities
                }
                
                print(f"  API URL: {filter_url}")
                print(f"  Parameters: {params}")
                
                response = requests.get(filter_url, headers=headers, params=params)
                
                print(f"  API response status: {response.status_code}")
                if response.status_code == 200:
                    data = response.json()
                    app_vulns = data.get('traces', [])
                    app_vulnerability_counts[app_name] = len(app_vulns)
                    
                    print(f"  Raw response data keys: {list(data.keys())}")
                    print(f"  Number of traces in response: {len(app_vulns)}")
                    
                    # Add app info to each vulnerability
                    for vuln in app_vulns:
                        vuln['app_name'] = app_name
                        vuln['app_id'] = app_id
                    
                    all_vulnerabilities.extend(app_vulns)
                    print(f"  Found {len(app_vulns)} vulnerabilities")
                else:
                    print(f"  ❌ Error: {response.status_code}")
                    print(f"  Error response: {response.text[:200]}")
                    app_vulnerability_counts[app_name] = 0
            except Exception as e:
                print(f"  ❌ Error: {e}")
                app_vulnerability_counts[app_name] = 0
        
        # Combine all vulnerabilities data
        combined_data = {
            'traces': all_vulnerabilities,
            'count': len(all_vulnerabilities),
            'applications': app_vulnerability_counts,
            'total_applications': len(applications)
        }
        
        # Save to JSON file
        with open("vulnerabilities_output.json", "w") as f:
            json.dump(combined_data, f, indent=2)
        print(f"\\nVulnerabilities response saved to vulnerabilities_output.json")
        
        # Display summary
        vulnerabilities = all_vulnerabilities
        total_count = len(vulnerabilities)
        
        print(f"\\nTotal Vulnerabilities Across All Applications: {total_count}")
        
        if vulnerabilities:
                print("\\nVulnerabilities found:")
                
                # Group by severity
                by_severity = {}
                by_status = {}
                by_category = {}
                
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'Unknown')
                    status = vuln.get('status', 'Unknown')
                    category = vuln.get('category', 'Unknown')
                    app_name = vuln.get('app_name', 'Unknown')
                    
                    # Count by severity
                    if severity not in by_severity:
                        by_severity[severity] = 0
                    by_severity[severity] += 1
                    
                    # Count by status
                    if status not in by_status:
                        by_status[status] = 0
                    by_status[status] += 1
                    
                    # Count by category
                    if category not in by_category:
                        by_category[category] = 0
                    by_category[category] += 1
                # Group by application
                by_application = {}
                
                for vuln in vulnerabilities:
                    app_name = vuln.get('app_name', 'Unknown')
                    if app_name not in by_application:
                        by_application[app_name] = 0
                    by_application[app_name] += 1
                
                # Display ALL vulnerabilities with detailed information
                print(f"\\nAll vulnerabilities found:")
                if len(vulnerabilities) == 0:
                    print("  (No vulnerabilities found)")
                else:
                    for i, vuln in enumerate(vulnerabilities, 1):
                        print(f"\\n{'=' * 80}")
                        print(f"VULNERABILITY #{i}")
                        print(f"{'=' * 80}")
                        
                        # Basic Information
                        print(f"Title: {vuln.get('title', 'N/A')}")
                        print(f"UUID: {vuln.get('uuid', 'N/A')}")
                        print(f"Application: {vuln.get('app_name', 'N/A')}")
                        print(f"Rule Name: {vuln.get('rule_name', 'N/A')}")
                        print(f"Rule Title: {vuln.get('rule_title', 'N/A')}")
                        
                        # Severity and Risk Assessment
                        print(f"\\n--- SEVERITY & RISK ---")
                        print(f"Severity: {vuln.get('severity', 'N/A')} (Default: {vuln.get('default_severity', 'N/A')})")
                        print(f"Impact: {vuln.get('impact', 'N/A')}")
                        print(f"Likelihood: {vuln.get('likelihood', 'N/A')}")
                        print(f"Confidence: {vuln.get('confidence', 'N/A')}")
                        
                        # Status and Tracking
                        print(f"\\n--- STATUS & TRACKING ---")
                        print(f"Status: {vuln.get('status', 'N/A')}")
                        print(f"Sub-status: {vuln.get('sub_status', 'N/A')}")
                        print(f"Category: {vuln.get('category', 'N/A')}")
                        print(f"Language: {vuln.get('language', 'N/A')}")
                        print(f"License: {vuln.get('license', 'N/A')}")
                        print(f"Visible: {vuln.get('visible', 'N/A')}")
                        
                        # Timestamps
                        print(f"\\n--- TIMELINE ---")
                        first_seen = vuln.get('first_time_seen', 'N/A')
                        last_seen = vuln.get('last_time_seen', 'N/A')
                        discovered = vuln.get('discovered', 'N/A')
                        
                        if first_seen != 'N/A':
                            import datetime
                            first_date = datetime.datetime.fromtimestamp(first_seen/1000).strftime('%Y-%m-%d %H:%M:%S')
                            print(f"First Seen: {first_date} ({first_seen})")
                        else:
                            print(f"First Seen: {first_seen}")
                            
                        if last_seen != 'N/A':
                            last_date = datetime.datetime.fromtimestamp(last_seen/1000).strftime('%Y-%m-%d %H:%M:%S')
                            print(f"Last Seen: {last_date} ({last_seen})")
                        else:
                            print(f"Last Seen: {last_seen}")
                            
                        if discovered != 'N/A':
                            discovered_date = datetime.datetime.fromtimestamp(discovered/1000).strftime('%Y-%m-%d %H:%M:%S')
                            print(f"Discovered: {discovered_date} ({discovered})")
                        else:
                            print(f"Discovered: {discovered}")
                        
                        print(f"Total Traces Received: {vuln.get('total_traces_received', 'N/A')}")
                        
                        # Application Details
                        app_info = vuln.get('application', {})
                        if app_info:
                            print(f"\\n--- APPLICATION DETAILS ---")
                            print(f"App ID: {app_info.get('app_id', 'N/A')}")
                            print(f"Language: {app_info.get('language', 'N/A')}")
                            print(f"Context Path: {app_info.get('context_path', 'N/A')}")
                            print(f"Importance: {app_info.get('importance_description', 'N/A')} ({app_info.get('importance', 'N/A')})")
                            print(f"License Level: {app_info.get('license_level', 'N/A')}")
                            print(f"Total Modules: {app_info.get('total_modules', 'N/A')}")
                        
                        # Request Details
                        request_info = vuln.get('request', {})
                        if request_info:
                            print(f"\\n--- HTTP REQUEST DETAILS ---")
                            print(f"Method: {request_info.get('method', 'N/A')}")
                            print(f"URI: {request_info.get('uri', 'N/A')}")
                            print(f"Protocol: {request_info.get('protocol', 'N/A')} {request_info.get('version', 'N/A')}")
                            print(f"Port: {request_info.get('port', 'N/A')}")
                            
                            headers = request_info.get('headers', [])
                            if headers:
                                print(f"Headers:")
                                for header in headers[:5]:  # Show first 5 headers
                                    print(f"  {header.get('name', 'N/A')}: {header.get('value', 'N/A')[:100]}{'...' if len(header.get('value', '')) > 100 else ''}")
                                if len(headers) > 5:
                                    print(f"  ... and {len(headers) - 5} more headers")
                        
                        # Events Timeline
                        events = vuln.get('events', [])
                        if events:
                            print(f"\\n--- EVENTS TIMELINE ---")
                            for event in events:
                                print(f"  Event ID: {event.get('eventId', 'N/A')} - Type: {event.get('type', 'N/A')}")
                        
                        # Tags and Version Info
                        tags = vuln.get('tags', [])
                        app_version_tags = vuln.get('app_version_tags', [])
                        if tags or app_version_tags:
                            print(f"\\n--- TAGS & VERSIONS ---")
                            if tags:
                                print(f"Tags: {', '.join(tags)}")
                            if app_version_tags:
                                print(f"App Versions: {', '.join(app_version_tags)}")
                        
                        # Bug Tracker Information
                        bugtracker_tickets = vuln.get('bugtracker_tickets', [])
                        reported_to_bug_tracker = vuln.get('reported_to_bug_tracker', False)
                        if reported_to_bug_tracker or bugtracker_tickets:
                            print(f"\\n--- BUG TRACKER ---")
                            print(f"Reported to Bug Tracker: {reported_to_bug_tracker}")
                            if bugtracker_tickets:
                                print(f"Tickets: {bugtracker_tickets}")
                        
                        # Additional Technical Details
                        print(f"\\n--- TECHNICAL DETAILS ---")
                        print(f"Instance UUID: {vuln.get('instance_uuid', 'N/A')}")
                        print(f"Vulnerability UUID: {vuln.get('vulnerability_uuid', 'N/A')}")
                        print(f"Sub Title: {vuln.get('sub_title', 'N/A')}")
                        print(f"Evidence: {vuln.get('evidence', 'N/A')}")
                        print(f"Violations: {len(vuln.get('violations', []))} violation(s)")
                        
                        # Organization Info
                        print(f"Organization: {vuln.get('organization_name', 'N/A')}")
                        
                        print(f"\\n{'-' * 80}")
                
                # Display summaries
                print(f"\\nVulnerabilities by severity:")
                severity_order = ['Critical', 'High', 'Medium', 'Low', 'Note', 'Unknown']
                for severity in severity_order:
                    if severity in by_severity:
                        print(f"  {severity}: {by_severity[severity]}")
                
                print(f"\\nVulnerabilities by status:")
                for status, count in sorted(by_status.items()):
                    print(f"  {status}: {count}")
                
                print(f"\\nVulnerabilities by application:")
                for app_name, count in sorted(by_application.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {app_name}: {count}")
                
                print(f"\\nTop vulnerability categories:")
                sorted_categories = sorted(by_category.items(), key=lambda x: x[1], reverse=True)
                for category, count in sorted_categories[:10]:  # Top 10
                    print(f"  {category}: {count}")
        else:
            print("No vulnerabilities found across all applications.")
            print("\\nApplication vulnerability summary:")
            for app_name, count in app_vulnerability_counts.items():
                print(f"  {app_name}: {count} vulnerabilities")
    
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