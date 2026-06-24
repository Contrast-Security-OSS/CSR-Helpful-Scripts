"""
Get traces using Contrast Security API client.
"""

import sys
import os
import json
from datetime import datetime

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
    """Get traces from Contrast Security."""
    
    print("=== Get Traces ===")
    
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
        
        # Get traces
        print("Fetching traces...")
        
        # Get the first 100 traces (traces can be quite numerous)
        response = client.traces.list(limit=100)
        
        if response.status_code == 200:
            data = response.json()
            
            # Save to JSON file
            with open("traces_output.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Traces response saved to traces_output.json")
            
            # Display summary
            traces = data.get('traces', [])
            print(f"\\nTotal Traces Retrieved: {len(traces)} (showing first 100)")
            
            if traces:
                print("\\nTraces found:")
                
                # Track statistics
                by_rule = {}
                by_severity = {}
                by_application = {}
                recent_traces = 0
                one_week_ago = datetime.now().timestamp() * 1000 - (7 * 24 * 60 * 60 * 1000)
                
                for trace in traces:
                    trace_id = trace.get('uuid', 'N/A')
                    title = trace.get('title', 'N/A')
                    app_name = trace.get('application', {}).get('name', 'N/A')
                    rule_name = trace.get('rule_name', 'N/A')
                    rule_title = trace.get('rule_title', 'N/A')
                    severity = trace.get('severity', 'N/A')
                    language = trace.get('language', 'N/A')
                    last_time_seen = trace.get('last_time_seen', 0)
                    status = trace.get('status', 'N/A')
                    
                    print(f"  - {title}")
                    print(f"    ID: {trace_id}")
                    print(f"    Application: {app_name}")
                    print(f"    Rule: {rule_name}")
                    print(f"    Severity: {severity}")
                    print(f"    Language: {language}")
                    print(f"    Status: {status}")
                    print(f"    Last Seen: {datetime.fromtimestamp(last_time_seen/1000) if last_time_seen else 'N/A'}")
                    print()
                    
                    # Track rule stats
                    if rule_title not in by_rule:
                        by_rule[rule_title] = 0
                    by_rule[rule_title] += 1
                    
                    # Track severity stats
                    if severity not in by_severity:
                        by_severity[severity] = 0
                    by_severity[severity] += 1
                    
                    # Track application stats
                    if app_name not in by_application:
                        by_application[app_name] = 0
                    by_application[app_name] += 1
                    
                    # Track recent traces
                    if last_time_seen > one_week_ago:
                        recent_traces += 1
                
                # Display summaries
                print(f"\\nTraces by severity:")
                severity_order = ['Critical', 'High', 'Medium', 'Low', 'Note', 'N/A']
                for severity in severity_order:
                    if severity in by_severity:
                        print(f"  {severity}: {by_severity[severity]}")
                
                print(f"\\nTop applications by trace count:")
                sorted_apps = sorted(by_application.items(), key=lambda x: x[1], reverse=True)
                for app_name, count in sorted_apps[:10]:  # Top 10
                    print(f"  {app_name}: {count}")
                
                print(f"\\nTop rules by trace count:")
                sorted_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)
                for rule_title, count in sorted_rules[:10]:  # Top 10
                    print(f"  {rule_title}: {count}")
                
                print(f"\\nTrace Activity Summary:")
                print(f"  Traces seen in last 7 days: {recent_traces}")
                print(f"  Older traces: {len(traces) - recent_traces}")
            else:
                print("No traces found.")
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