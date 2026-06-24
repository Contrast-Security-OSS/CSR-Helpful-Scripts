import requests
import base64
import getpass
import json
import csv
from collections import Counter
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

def load_payload(filename="payload.json"):
    """Load the POST body from a JSON file"""
    with open(filename, "r") as f:
        return json.load(f)

def get_attacks(headers, org_id, post_body, offset=0, limit=25):
    """Fetch attacks from the organization"""
    url = f"{contrast_url}/api/ng/{org_id}/attacks?expand=skip_links&limit={limit}&offset={offset}&sort=-startTime"

    response = requests.post(url, headers=headers, json=post_body)
    return response

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

def extract_attack_data(item):
    """Extract attack data from API response, one row per application"""
    rows = []
    apps = item.get("attacksApplication", [])
    rules = "; ".join(item.get("rules", []))
    servers = item.get("servers", [])
    server_names = "; ".join(s.get("name", "") for s in servers)
    server_ids = "; ".join(str(s.get("server_id", "")) for s in servers)
    server_envs = "; ".join(s.get("environment", "") for s in servers)

    if apps:
        for app_entry in apps:
            app = app_entry.get("application", {})
            rows.append({
                "Application Name": app.get("name", ""),
                "Rules": rules,
                "Server Environments": server_envs,
                "Status": app_entry.get("status", item.get("status", ""))

                #"Attack ID": item.get("uuid", ""),
                #"Attack Label": item.get("attack_label", ""),                
                #"Severity": app_entry.get("severity", ""),
                #"Type": item.get("type", ""),
                #"Source IP": item.get("source", ""),                
                #"Start Time": format_timestamp(item.get("start_time")),
                #"Start Date": format_date_only(item.get("start_time")),
                #"End Time": format_timestamp(item.get("end_time")),
                #"End Date": format_date_only(item.get("end_time")),                
                #"Application ID": app.get("app_id", ""),
                #"Application Language": app.get("language", ""),
                #"Server Names": server_names,
                #"Server IDs": server_ids,                
                #"Probes": item.get("probes", ""),
                #"Duration (ms)": item.get("attack_duration", ""),
            })
    else:
        rows.append({
            "Application Name": "",
            "Rules": rules,
            "Server Environments": server_envs,
            "Status": item.get("status", "")

            #"Attack ID": item.get("uuid", ""),
            #"Attack Label": item.get("attack_label", ""),            
            #"Severity": "",
            #"Type": item.get("type", ""),
            #"Source IP": item.get("source", ""),            
            #"Start Time": format_timestamp(item.get("start_time")),
            #"Start Date": format_date_only(item.get("start_time")),
            #"End Time": format_timestamp(item.get("end_time")),
            #"End Date": format_date_only(item.get("end_time")),
            #"Application ID": "",
            #"Application Language": "",
            #"Server Names": server_names,
            #"Server IDs": server_ids,            
            #"Probes": item.get("probes", ""),
            #"Duration (ms)": item.get("attack_duration", ""),
        })

    return rows

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

    # Prompt for date range
    default_start = '2020-01-01'
    default_end = datetime.now().strftime('%Y-%m-%d')

    msg = f"Enter start date (YYYY-MM-DD, blank will use today '{default_start}'): "
    start_date_input = input(msg)
    if start_date_input.strip():
        start_date_str = start_date_input.strip()
    else:
        start_date_str = default_start

    msg = f"Enter end date (YYYY-MM-DD, blank will use today '{default_end}'): "
    end_date_input = input(msg)
    if end_date_input.strip():
        end_date_str = end_date_input.strip()
    else:
        end_date_str = default_end

    # Convert dates to epoch milliseconds
    start_date_ms = str(int(datetime.strptime(start_date_str, '%Y-%m-%d').timestamp() * 1000))
    end_date_ms = str(int(datetime.strptime(end_date_str + " 23:59:59", '%Y-%m-%d %H:%M:%S').timestamp() * 1000))

    # Load payload from JSON file and set date range
    post_body = load_payload()
    post_body["startDate"] = start_date_ms
    post_body["endDate"] = end_date_ms

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
        "Application Name",
        "Rules",
        "Server Environments",
        "Status",
        "Count",
    ]

    # Fetch all attacks with pagination
    all_attacks = []
    offset = 0
    limit = 25
    total_count = None

    print(f"Fetching attacks from {start_date_str} to {end_date_str}...")

    while True:
        print(f"Fetching attacks {offset} to {offset + limit}...")
        response = get_attacks(headers, org_id, post_body, offset, limit)

        if response.status_code != 200:
            print(f"Error fetching attacks: {response.status_code}")
            print(f"Response: {response.text}")
            break

        data = response.json()

        # Debug: save raw response on first request to inspect structure
        if total_count is None:
            with open("attacks_raw_response.json", "w") as f:
                json.dump(data, f, indent=2)
            print(f"Raw API response saved to attacks_raw_response.json")

        # Get total count on first request
        if total_count is None:
            total_count = data.get("count", 0)
            print(f"Total attacks to fetch: {total_count}")

        items = data.get("attacks", data.get("items", []))
        if not items:
            break

        # Extract attack data
        for idx, item in enumerate(items):
            print(f"  Processing attack {offset + idx + 1}/{total_count}")
            attack_rows = extract_attack_data(item)
            all_attacks.extend(attack_rows)

        # Check if we've fetched all attacks
        offset += limit
        if offset >= total_count:
            break

    # Save to JSON for debugging
    with open("attacks_output.json", "w") as f:
        json.dump(all_attacks, f, indent=2)
    print(f"Raw data saved to attacks_output.json")

    # Aggregate by Application Name, Rules, Server Environments, Status
    counts = Counter(
        (row["Application Name"], row["Rules"], row["Server Environments"], row["Status"])
        for row in all_attacks
    )

    aggregated = []
    for (app_name, rules, server_envs, status), count in counts.most_common():
        aggregated.append({
            "Application Name": app_name,
            "Rules": rules,
            "Server Environments": server_envs,
            "Status": status,
            "Count": count,
        })

    # Write to CSV
    csv_filename = "attacks_export.csv"
    with open(csv_filename, "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
        writer.writeheader()
        writer.writerows(aggregated)

    print(f"\nExport complete!")
    print(f"Total attack rows (before aggregation): {len(all_attacks)}")
    print(f"Unique combinations exported: {len(aggregated)}")
    print(f"CSV file created: {csv_filename}")

if __name__ == "__main__":
    main()
