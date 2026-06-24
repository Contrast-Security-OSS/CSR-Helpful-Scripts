# SPDX-License-Identifier: Apache-2.0
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import base64
import getpass  # For secure password input (hides input from display)
import json
import csv
import os
import sys
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

params = {
    "expand": ["apps"]
}

def getServers(session, headers, params, org_id, contrast_url):
    """Fetch all servers from the Contrast API"""
    url = f"{contrast_url}/api/ng/{org_id}/servers"
    response = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    return response

def getServer(session, headers, params, org_id, server_id, contrast_url):
    """Fetch individual server details including applications"""
    url = f"{contrast_url}/api/ng/{org_id}/servers/{server_id}"
    response = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    return response

def read_json_file(filename):
    """Helper function to read JSON files"""
    with open(filename, "r") as f:
        return f.read()

def main():
    parser = argparse.ArgumentParser(description="Report applications by language for servers in the Contrast org.")
    parser.add_argument("--server-ids", help="Comma-separated server IDs to filter on (default: no filter).")
    parser.add_argument("--server-ids-file", help="Path to file with one server ID per line.")
    parser.add_argument("--debug-dir", default=None,
                        help="Optional directory for debug JSON dumps. When omitted, nothing is written to disk.")
    parser.add_argument("--debug", action="store_true",
                        help="Print full response body on error (default: status code only).")
    args = parser.parse_args()

    # Get credentials using the shared module
    creds = get_credentials()
    contrast_url = creds["contrast_url"]
    org_id = creds["org_id"]
    headers = creds["headers"]

    # Optional server-ID filter list (empty by default; no filter applied when empty).
    servers_list = _parse_server_ids(args)

    session = _make_session()

    # Fetch all servers from the API
    response = getServers(session, headers, params, org_id, contrast_url)
    if response.status_code == 200:  # HTTP 200 means success
        data = response.json()  # Parse JSON response into Python dict
        # Optionally save the response for debugging.
        _write_debug_json(args.debug_dir, "output.json", data)
        print("Applications that are running on servers, any missing applications are not running on servers.")

        # Set params to expand applications data when fetching individual servers
        server_params = {
            "expand": ["applications"]  # Tell API to include application details
        }

        # Initialize CSV data structures for language tracking
        csv_data = []  # Will hold all the data rows for CSV output
        # Define all supported programming languages for applications
        csv_headers = ["Java", ".NET Framework", ".NET Core", "Node", "Ruby", "Proxy", "Python", "Go", "PHP", "Other"]
        csv_totals = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # Counter for each language (running totals)

        # Process servers if they exist in the response
        if data.get("servers"):  # .get() safely checks if 'servers' key exists
            applications = []
            server_list = data["servers"]  # Extract the servers array
            for server in server_list:
                server_id = server.get("server_id")
                # Apply optional filter when caller supplied --server-ids / --server-ids-file.
                if servers_list and server_id not in servers_list:
                    continue
                # Fetch detailed server information including applications
                server_data = getServer(session, headers, server_params, org_id, server_id, contrast_url).json()

                # Extract applications array from nested server data structure
                applications = server_data.get('server').get('applications', [])

                # Process each application on this server
                for app in applications:

                    # Initialize row data: one slot for each language type (0 = not this language, 1 = is this language)
                    csv_row = ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]

                    # Get the application's programming language, default to 'Other' if not specified
                    app_language = app.get('language', 'Other')

                    # Use match-case (Python 3.10+) to categorize application by language
                    match app_language:
                        case "Java":
                            csv_row[0] = "1"  # Mark as Java application
                            csv_totals[0] += 1  # Increment Java counter
                        case ".NET Framework":
                            csv_row[1] = "1"  # Mark as .NET Framework application
                            csv_totals[1] += 1  # Increment .NET Framework counter
                        case ".NET Core":
                            csv_row[2] = "1"  # Mark as .NET Core application
                            csv_totals[2] += 1  # Increment .NET Core counter
                        case "Node":
                            csv_row[3] = "1"  # Mark as Node.js application
                            csv_totals[3] += 1  # Increment Node counter
                        case "Ruby":
                            csv_row[4] = "1"  # Mark as Ruby application
                            csv_totals[4] += 1  # Increment Ruby counter
                        case "Proxy":
                            csv_row[5] = "1"  # Mark as Proxy application
                            csv_totals[5] += 1  # Increment Proxy counter
                        case "Python":
                            csv_row[6] = "1"  # Mark as Python application
                            csv_totals[6] += 1  # Increment Python counter
                        case "Go":
                            csv_row[7] = "1"  # Mark as Go application
                            csv_totals[7] += 1  # Increment Go counter
                        case "PHP":
                            csv_row[8] = "1"  # Mark as PHP application
                            csv_totals[8] += 1  # Increment PHP counter
                        case _:  # Default case for any language not explicitly handled above
                            csv_row[9] = "1"  # Mark as Other language application
                            csv_totals[9] += 1  # Increment Other counter

                    csv_data.append(csv_row)  # Add this row to our data collection

                    # Write all collected data to CSV file (overwritten each time - could be moved outside loop for efficiency)
                    with open("application_languages.csv", "w", newline='', encoding='utf-8') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(csv_headers)  # Write column headers as first row
                        writer.writerows(csv_data)    # Write all data rows
                        writer.writerow([])           # Add blank row for visual separation
                        writer.writerow(csv_totals)   # Write totals row at bottom

            # Display summary results to user in terminal
            print("\n\nApplications by Languages:")
            print("------------------------------")
            for lang in csv_headers:
                # Get the index position of this language in the headers array
                if csv_totals[csv_headers.index(lang)] > 0:  # Only show languages with count > 0 (comment this line out to show all)
                    print(f"{lang}: {csv_totals[csv_headers.index(lang)]}")

        else:
            print("No servers found in response.")
            return  # Exit function early if no servers
    else:
        # Display error if API call failed (non-200 status code)
        print(f"Request failed: HTTP {response.status_code}")
        if args.debug:
            print(response.text)

# Only run main() if this script is executed directly (not imported)
if __name__ == "__main__":
    main()
