"""
Get attacks using Contrast Security API client.
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
    """Get attacks from Contrast Security."""
    
    print("=== Get Attacks ===")
    
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
        
        # Get attacks
        print("Fetching attacks...")
        
        # Get the first 100 attacks (attacks can be quite numerous)
        response = client.attacks.list(limit=100)
        
        if response.status_code == 200:
            data = response.json()
            
            # Save to JSON file
            with open("attacks_output.json", "w") as f:
                json.dump(data, f, indent=2)
            print("Attacks response saved to attacks_output.json")
            
            # Display summary
            attacks = data.get('attacks', [])
            print(f"\\nTotal Attacks Retrieved: {len(attacks)} (showing first 100)")
            
            if attacks:
                print("\\nAttacks found:")
                
                # Track statistics
                by_rule = {}
                by_severity = {}
                by_application = {}
                by_result = {}
                recent_attacks = 0
                blocked_attacks = 0
                one_week_ago = datetime.now().timestamp() * 1000 - (7 * 24 * 60 * 60 * 1000)
                
                for attack in attacks:
                    attack_id = attack.get('uuid', 'N/A')
                    app_name = attack.get('application', {}).get('name', 'N/A')
                    rule_name = attack.get('rule', {}).get('name', 'N/A')
                    rule_title = attack.get('rule', {}).get('title', 'N/A')
                    severity = attack.get('rule', {}).get('severity', 'N/A')
                    result = attack.get('result', 'N/A')
                    timestamp = attack.get('timestamp', 0)
                    request_method = attack.get('request', {}).get('method', 'N/A')
                    request_uri = attack.get('request', {}).get('uri', 'N/A')
                    
                    print(f"  - Attack {attack_id}")
                    print(f"    Application: {app_name}")
                    print(f"    Rule: {rule_title} ({rule_name})")
                    print(f"    Severity: {severity}")
                    print(f"    Result: {result}")
                    print(f"    Time: {datetime.fromtimestamp(timestamp/1000) if timestamp else 'N/A'}")
                    print(f"    Request: {request_method} {request_uri}")
                    
                    if result == 'Blocked':
                        print(f"    🛡️ Attack was BLOCKED")
                    elif result == 'Monitored':
                        print(f"    ⚠️ Attack was MONITORED only")
                    
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
                    
                    # Track result stats
                    if result not in by_result:
                        by_result[result] = 0
                    by_result[result] += 1
                    
                    # Track recent attacks
                    if timestamp > one_week_ago:
                        recent_attacks += 1
                    
                    # Track blocked attacks
                    if result == 'Blocked':
                        blocked_attacks += 1
                
                # Display summaries
                print(f"\\nAttacks by severity:")
                severity_order = ['Critical', 'High', 'Medium', 'Low', 'Note', 'N/A']
                for severity in severity_order:
                    if severity in by_severity:
                        print(f"  {severity}: {by_severity[severity]}")
                
                print(f"\\nAttacks by result:")
                for result, count in sorted(by_result.items()):
                    icon = "🛡️" if result == "Blocked" else "⚠️" if result == "Monitored" else "❓"
                    print(f"  {icon} {result}: {count}")
                
                print(f"\\nTop targeted applications:")
                sorted_apps = sorted(by_application.items(), key=lambda x: x[1], reverse=True)
                for app_name, count in sorted_apps[:10]:  # Top 10
                    print(f"  {app_name}: {count} attacks")
                
                print(f"\\nTop attack rules:")
                sorted_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)
                for rule_title, count in sorted_rules[:10]:  # Top 10
                    print(f"  {rule_title}: {count}")
                
                print(f"\\nAttack Activity Summary:")
                print(f"  Attacks in last 7 days: {recent_attacks}")
                print(f"  Older attacks: {len(attacks) - recent_attacks}")
                print(f"  Blocked attacks: {blocked_attacks}")
                print(f"  Monitored attacks: {len(attacks) - blocked_attacks}")
                
                if len(attacks) > 0:
                    block_rate = (blocked_attacks / len(attacks)) * 100
                    print(f"  Block rate: {block_rate:.1f}%")
            else:
                print("No attacks found.")
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