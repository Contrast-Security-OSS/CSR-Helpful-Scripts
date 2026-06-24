# SPDX-License-Identifier: Apache-2.0
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import base64
import getpass
import json
import sys
import os
import argparse

# Add the directory containing this script and its parent to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.insert(0, script_dir)  # Add current script directory
sys.path.insert(0, parent_dir)  # Add parent directory

try:
    from fetch_creds import get_credentials
except ImportError:
    print("Error: Cannot find fetch_creds module. Make sure fetch_creds.py is in the parent directory.")
    sys.exit(1)
import csv

HTTP_TIMEOUT = (10, 60)

def _make_session():
    s = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]),
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s

def _write_debug_json(debug_dir, filename, data):
    """Write JSON to debug_dir/filename with 0700 dir and 0600 file. No-op when debug_dir is None."""
    if not debug_dir:
        return
    target_dir = os.path.expanduser(debug_dir)
    os.makedirs(target_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(target_dir, 0o700)
    except OSError:
        pass
    target_path = os.path.join(target_dir, filename)
    with open(target_path, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(target_path, 0o600)
    except OSError:
        pass

def _parse_server_ids(args):
    """Return list of server IDs (ints) from CLI args; empty list means no filter."""
    if args.server_ids:
        return [int(x.strip()) for x in args.server_ids.split(",") if x.strip()]
    if args.server_ids_file:
        path = os.path.expanduser(args.server_ids_file)
        with open(path, "r") as f:
            return [int(line.strip()) for line in f if line.strip()]
    return []

class Application:
    def __init__(self, app_id, name):
        self.app_id = app_id
        self.name = name

def read_creds_file(filename="../.creds"):
    """Read credentials from a .creds file"""
    creds = {}
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()  # Remove whitespace from beginning and end of line
                # Skip empty lines and comment lines that start with #
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)  # Split on first = only
                    creds[key] = value
    except FileNotFoundError:
        print(f"Warning: {filename} file not found. Please input values.")
    return creds

# Read credentials from .creds file
creds = read_creds_file()

# Set the default values for re-using within your organization from .creds file
contrast_url = creds.get("CONTRAST_URL", "")
org_id = creds.get("ORG_ID", "")
username = creds.get("USERNAME", "")
api_key = creds.get("API_KEY", "")
service_key = creds.get("SERVICE_KEY", "")
app_id = creds.get("APP_ID", "")

# Encode credentials for Basic Authentication
auth_str = f"{username}:{service_key}"
auth_b64 = base64.b64encode(auth_str.encode()).decode()

# Set up HTTP headers for API requests
headers = {
    "Accept": "application/json"
}
# Set up query parameters to expand server data
params = {
    "expand": ["apps"]
}

def getServers(session, headers, params, org_id):
    """Fetch all servers from the Contrast API"""
    url = f"{contrast_url}/api/ng/{org_id}/servers"
    response = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    return response

def getServer(session, headers, params, org_id, server_id):
    """Fetch individual server details including applications"""
    url = f"{contrast_url}/api/ng/{org_id}/servers/{server_id}"
    response = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    return response

def read_json_file(filename):
    """Helper function to read JSON files"""
    with open(filename, "r") as f:
        return f.read()

def main():
    # Allow modification of global variables within this function
    global contrast_url, org_id, username, api_key, service_key

    parser = argparse.ArgumentParser(description="Report Protect vs Assess license coverage across servers.")
    parser.add_argument("--server-ids", help="Comma-separated server IDs to filter on (default: no filter).")
    parser.add_argument("--server-ids-file", help="Path to file with one server ID per line.")
    parser.add_argument("--debug-dir", default=None,
                        help="Optional directory for debug JSON dumps. When omitted, nothing is written to disk.")
    parser.add_argument("--debug", action="store_true",
                        help="Print full response body on error (default: status code only).")
    args = parser.parse_args()

    # Prompt user for Contrast URL, use default from .creds if blank
    msg = f"Enter your Contrast URL (blank will use default '{contrast_url}'): "
    contrast_url_input = input(msg)
    if contrast_url_input.strip():
        contrast_url = contrast_url_input
    else:
        # Keep prompting if no default exists and user provides blank input
        while not contrast_url_input.strip() and not contrast_url.strip():
            print("Contrast URL cannot be blank.")
            contrast_url_input = input(msg)
            contrast_url = contrast_url_input

    # Prompt user for Organization ID, use default from .creds if blank
    msg = f"Enter your Organization ID (blank will use default '{org_id}'): "
    org_id_input = input(msg)
    if org_id_input.strip():
        org_id = org_id_input
    else:
        # Keep prompting if no default exists and user provides blank input
        while not org_id_input.strip() and not org_id.strip():
            print("Organization ID cannot be blank.")
            org_id_input = input(msg)
            org_id = org_id_input

    # Prompt user for username, use default from .creds if blank
    msg = f"Enter your username (blank will use default '{username}'): "
    username_input = input(msg)
    if username_input.strip():
        username = username_input
    else:
        # Keep prompting if no default exists and user provides blank input
        while not username_input.strip() and not username.strip():
            print("Username cannot be blank.")
            username_input = input(msg)
            username = username_input

    # Prompt user for API key (hidden input), use default from .creds if blank
    msg = f"Enter your API key (blank will use default '****************************'): "
    api_key_input = getpass.getpass(msg)  # getpass hides the input from display
    if api_key_input.strip():
        api_key = api_key_input
    else:
        # Keep prompting if no default exists and user provides blank input
        while not api_key_input.strip() and not api_key.strip():
            print("API key cannot be blank.")
            api_key_input = getpass.getpass(msg)
            api_key = api_key_input

    # Prompt user for service key (hidden input), use default from .creds if blank
    msg = f"Enter your service key (blank will use default '************'): "
    service_key_input = getpass.getpass(msg)  # getpass hides the input from display
    if service_key_input.strip():
        service_key = service_key_input
    else:
        # Keep prompting if no default exists and user provides blank input
        while not service_key_input.strip() and not service_key.strip():
            print("Service key cannot be blank.")
            service_key_input = getpass.getpass(msg)
            service_key = service_key_input

    # Optional server-ID filter list (empty by default; no filter applied when empty).
    servers_list = _parse_server_ids(args)

    # Create Basic Authentication header with encoded credentials
    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    headers["Authorization"] = f"Basic {auth_b64}"
    headers["API-Key"] = api_key

    session = _make_session()

    # Fetch all servers from the API
    response = getServers(session, headers, params, org_id)
    if response.status_code == 200:
        data = response.json()

        # Optionally save the response for debugging.
        _write_debug_json(args.debug_dir, "output.json", data)

        # Set params to expand applications data when fetching individual servers
        server_params = {
            "expand": ["applications"]
        }

        # Initialize CSV data structures
        csv_data = []  # Will hold all the data rows
        csv_headers = ["assess_count", "protect_count", "both_count"]
        csv_totals = [0, 0, 0]  # Counter for assess, protect, and both (running totals)

        # Process servers if they exist in the response
        if data.get("servers"):
            applications = []
            server_list = data["servers"]
            for server in server_list:
                server_id = server.get("server_id")
                # Apply optional filter when caller supplied --server-ids / --server-ids-file.
                if servers_list and server_id not in servers_list:
                    continue
                # Fetch detailed server information including applications
                server_data = getServer(session, headers, server_params, org_id, server_id).json()

                # Extract applications array from server data
                applications = server_data.get('server').get('applications', [])

                # Check if server has assess and protect sensors enabled
                assess = server_data.get('server').get('assess_sensors', False)
                protect = server_data.get('server').get('defend_sensors', False)

                # Process each application on this server
                for app in applications:
                    # App has assess if server has assess AND app is not unlicensed
                    app['assess'] = assess and app.get('license_level', '') != 'Unlicensed'
                    # App has protect if server has protect enabled
                    app['protect'] = protect

                    # Initialize row data: [assess_count, protect_count, both_count]
                    csv_row = ["0", "0", "0"]

                    # Set flags and increment counters based on app capabilities
                    if app['assess']:
                        csv_row[0] = "1"  # Mark as having assess
                        csv_totals[0] += 1  # Increment assess total count
                    if app['protect']:
                        csv_row[1] = "1"  # Mark as having protect
                        csv_totals[1] += 1  # Increment protect total count
                    if app['assess'] and app['protect']:
                        csv_row[2] = "1"  # Mark as having both
                        csv_totals[2] += 1  # Increment both total count

                    csv_data.append(csv_row)  # Add this row to our data collection

            # Write all collected data to CSV file
            with open("protect_vs_assess_report.csv", "w", newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(csv_headers)  # Write column headers
                writer.writerows(csv_data)    # Write all data rows
                writer.writerow([])           # Add blank row for separation
                writer.writerow(csv_totals)   # Write totals row

            # Display summary results to user
            print("\n\nApplications by Licensed:")
            print("------------------------------")
            for lic in csv_headers:
                # Get the index position of this license type in the headers array
                index = csv_headers.index(lic)
                # Only display license types that have a count > 0
                if csv_totals[index] > 0:  # Comment this line out to show all types including 0 counts
                    print(f"{lic}: {csv_totals[index]}")

        else:
            print("No servers found in response.")
            return
    else:
        # Display error if API call failed
        print(f"Request failed: HTTP {response.status_code}")
        if args.debug:
            print(response.text)

if __name__ == "__main__":
    main()
