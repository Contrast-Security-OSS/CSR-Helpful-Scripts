import requests
import base64
import getpass
import json
import csv
from datetime import datetime

def read_creds_file(filename="../.creds"):
    """Read credentials from a .creds file"""
    creds = {}
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    creds[key] = value
    except FileNotFoundError:
        print(f"Warning: {filename} file not found. Please input values.")
    return creds

def get_vulnerabilities(headers, org_id, offset=0, limit=100):
    """Fetch vulnerabilities from the organization"""
    url = f"{contrast_url}/api/ng/organizations/{org_id}/orgtraces/ui?expand=application,session_metadata&offset={offset}&limit={limit}&sort=-severity"

    # POST body with filter parameters
    post_body = {
        "quickFilter": "OPEN",
        "modules": [],
        "servers": [],
        "filterTags": [],
        "severities": [],
        "status": [],
        "substatus": [],
        "vulnTypes": [],
        "environments": [],
        "urls": [],
        "sinks": [],
        "securityStandards": [],
        "appVersionTags": [],
        "routes": [],
        "tracked": False,
        "untracked": False,
        "technologies": [],
        "applicationTags": [],
        "applicationMetadataFilters": [],
        "applicationImportances": [],
        "languages": [],
        "licensedOnly": False,
        "protectStatuses": []
    }
    response = requests.post(url, headers=headers, json=post_body)
    return response

def get_vulnerability_cwe(headers, org_id, vuln_id):
    """Fetch CWE information for a specific vulnerability"""
    url = f"{contrast_url}/api/ng/{org_id}/traces/{vuln_id}/recommendation?expand=skip_links"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            cwe_url = data.get("recommendation", {}).get("cwe", "")
            if cwe_url:
                # Extract CWE ID from URL (e.g., "https://cwe.mitre.org/data/definitions/89.html" -> "CWE-89")
                if "/" in cwe_url:
                    cwe_number = cwe_url.rstrip("/").split("/")[-1].replace(".html", "")
                    return f"CWE-{cwe_number}"
            return cwe_url
        return ""
    except Exception as e:
        print(f"Error fetching CWE for {vuln_id}: {e}")
        return ""

def format_timestamp(timestamp):
    """Convert millisecond timestamp to readable format"""
    if timestamp:
        return datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
    return ""

def format_date_only(timestamp):
    """Convert millisecond timestamp to date only"""
    if timestamp:
        return datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d')
    return ""

def extract_vulnerability_data(item, headers, org_id):
    """Extract vulnerability data from API response"""
    vuln = item.get("vulnerability", {})
    app = vuln.get("application", {})
    bug_tracker = vuln.get("bugTracker", {})
    vuln_id = vuln.get("uuid", "")

    # Extract bug tracker information
    bug_tracker_id = ""
    bug_tracker_url = ""
    bug_tracker_tickets = bug_tracker.get("bugTrackerTickets", [])
    if bug_tracker_tickets and len(bug_tracker_tickets) > 0:
        first_ticket = bug_tracker_tickets[0]
        bug_tracker_id = first_ticket.get("ticketKey", "")
        bug_tracker_url = first_ticket.get("ticketUrl", "")

    # Get CWE ID from recommendation endpoint
    cwe_id = ""
    if vuln_id:
        cwe_id = get_vulnerability_cwe(headers, org_id, vuln_id)

    # Get parent application name (directly from application object)
    parent_app_name = app.get("parentApplicationName", "")

    return {
        "Vulnerability Name": vuln.get("title", ""),
        "Vulnerability ID": vuln.get("uuid", ""),
        "Rule Name": vuln.get("ruleName", ""),
        "Severity": vuln.get("severity", ""),
        "Status": vuln.get("status", ""),
        "First Seen": format_date_only(vuln.get("firstDetected")),
        "First Seen Datetime": format_timestamp(vuln.get("firstDetected")),
        "Last Seen": format_date_only(vuln.get("lastDetected")),
        "Last Seen Datetime": format_timestamp(vuln.get("lastDetected")),
        "Application Name": app.get("name", ""),
        "Application ID": app.get("id", ""),
        "Application Code": app.get("contextPath", ""),
        "Parent Application Name": parent_app_name,
        "CWE ID": cwe_id,
        "Bug Tracker ID": bug_tracker_id,
        "Bug Tracker URL": bug_tracker_url
    }

def main():
    # Read credentials from .creds file
    creds = read_creds_file()

    global contrast_url
    contrast_url = creds.get("CONTRAST_URL", "")
    org_id = creds.get("ORG_ID", "")
    username = creds.get("USERNAME", "")
    api_key = creds.get("API_KEY", "")
    service_key = creds.get("SERVICE_KEY", "")

    # Prompt for credentials if not in .creds file
    msg = f"Enter your Contrast URL (blank will use default '{contrast_url}'): "
    contrast_url_input = input(msg)
    if contrast_url_input.strip():
        contrast_url = contrast_url_input
    else:
        while not contrast_url_input.strip() and not contrast_url.strip():
            print("Contrast URL cannot be blank.")
            contrast_url_input = input(msg)
            contrast_url = contrast_url_input

    msg = f"Enter your Organization ID (blank will use default '{org_id}'): "
    org_id_input = input(msg)
    if org_id_input.strip():
        org_id = org_id_input
    else:
        while not org_id_input.strip() and not org_id.strip():
            print("Organization ID cannot be blank.")
            org_id_input = input(msg)
            org_id = org_id_input

    msg = f"Enter your username (blank will use default '{username}'): "
    username_input = input(msg)
    if username_input.strip():
        username = username_input
    else:
        while not username_input.strip() and not username.strip():
            print("Username cannot be blank.")
            username_input = input(msg)
            username = username_input

    msg = f"Enter your API key (blank will use default '****************************'): "
    api_key_input = getpass.getpass(msg)
    if api_key_input.strip():
        api_key = api_key_input
    else:
        while not api_key_input.strip() and not api_key.strip():
            print("API key cannot be blank.")
            api_key_input = getpass.getpass(msg)
            api_key = api_key_input

    msg = f"Enter your service key (blank will use default '************'): "
    service_key_input = getpass.getpass(msg)
    if service_key_input.strip():
        service_key = service_key_input
    else:
        while not service_key_input.strip() and not service_key.strip():
            print("Service key cannot be blank.")
            service_key_input = getpass.getpass(msg)
            service_key = service_key_input

    # Setup authentication headers
    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_b64}",
        "API-Key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    # Define CSV headers
    csv_headers = [
        "Vulnerability Name",
        "Vulnerability ID",
        "Rule Name",
        "Severity",
        "Status",
        "First Seen",
        "First Seen Datetime",
        "Last Seen",
        "Last Seen Datetime",
        "Application Name",
        "Application ID",
        "Application Code",
        "Parent Application Name",
        "CWE ID",
        "Bug Tracker ID",
        "Bug Tracker URL"
    ]

    # Fetch all vulnerabilities with pagination
    all_vulnerabilities = []
    offset = 0
    limit = 100
    total_count = None

    print("Fetching vulnerabilities...")

    while True:
        print(f"Fetching vulnerabilities {offset} to {offset + limit}...")
        response = get_vulnerabilities(headers, org_id, offset, limit)

        if response.status_code != 200:
            print(f"Error fetching vulnerabilities: {response.status_code}")
            print(f"Response: {response.text}")
            break

        data = response.json()

        # Get total count on first request
        if total_count is None:
            total_count = data.get("count", 0)
            print(f"Total vulnerabilities to fetch: {total_count}")

        items = data.get("items", [])
        if not items:
            break

        # Extract vulnerability data
        for idx, item in enumerate(items):
            vuln_id = item.get("vulnerability", {}).get("uuid", "")
            print(f"  Processing vulnerability {offset + idx + 1}/{total_count}: {vuln_id}")
            vuln_data = extract_vulnerability_data(item, headers, org_id)
            all_vulnerabilities.append(vuln_data)

        # Check if we've fetched all vulnerabilities
        offset += limit
        if offset >= total_count:
            break

    # Save to JSON for debugging
    with open("vulnerabilities_output.json", "w") as f:
        json.dump(all_vulnerabilities, f, indent=2)
    print(f"Raw data saved to vulnerabilities_output.json")

    # Write to CSV
    csv_filename = "vulnerabilities_export.csv"
    with open(csv_filename, "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
        writer.writeheader()
        writer.writerows(all_vulnerabilities)

    print(f"\nExport complete!")
    print(f"Total vulnerabilities exported: {len(all_vulnerabilities)}")
    print(f"CSV file created: {csv_filename}")

if __name__ == "__main__":
    main()
