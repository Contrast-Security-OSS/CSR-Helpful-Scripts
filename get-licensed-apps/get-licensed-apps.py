# SPDX-License-Identifier: Apache-2.0
import requests
import base64
import getpass
import json
import csv  # Add csv import for proper CSV handling
import sys
import os
import argparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

from contrast_security.utils import safe_csv_cell

include_protect_server_info = True

def _make_session():
    s = requests.Session()
    retry = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], respect_retry_after_header=True, allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s

class Application:
    def __init__(self, app_id, name):
        self.app_id = app_id
        self.name = name

params = {
    "expand": ["apps", "vulns"]
}

def getApplications(session, headers, params, org_id, contrast_url):
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    response = session.get(url, headers=headers, params=params, timeout=(10, 60))
    return response

def getServers(session, headers, params, org_id):
    url = f"{contrast_url}/api/ng/{org_id}/servers"
    response = session.get(url, headers=headers, params=params, timeout=(10, 60))
    return response

def getLink(session, headers, params, link, contrast_url):
    url = f"{contrast_url}/api{link}"
    response = session.get(url, headers=headers, params=params, timeout=(10, 60))
    return response

def putToggleServerProtect(session, headers, params, org_id, server_id):
    url = f"{contrast_url}/api/ng/{org_id}/servers/{server_id}/defend"
    response = session.put(url, headers=headers, params=params, timeout=(10, 60))
    return response

def read_json_file(filename):
    with open(filename, "r") as f:
        return f.read()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug-dir", default=None, help="Optional directory for debug JSON dumps (e.g. ~/.contrast-csr/)")
    args = parser.parse_args()

    # Get credentials using the shared module
    creds = get_credentials()
    contrast_url = creds["contrast_url"]
    org_id = creds["org_id"]
    headers = creds["headers"]

    session = _make_session()

    # Paginate /applications. Aggregate until short page or empty.
    limit = 50
    offset = 0
    all_applications = []
    last_response = None
    while True:
        page_params = dict(params)
        page_params["offset"] = offset
        page_params["limit"] = limit
        response = getApplications(session, headers, params=page_params, org_id=org_id, contrast_url=contrast_url)
        last_response = response
        if response.status_code != 200:
            break
        page_data = response.json()
        page_apps = page_data.get("applications", []) or []
        all_applications.extend(page_apps)
        if len(page_apps) < limit:
            break
        offset += limit

    response = last_response
    if response is not None and response.status_code == 200:
        data = {"applications": all_applications}
        if args.debug_dir:
            debug_dir = os.path.expanduser(args.debug_dir)
            os.makedirs(debug_dir, exist_ok=True, mode=0o700)
            debug_path = os.path.join(debug_dir, "output.json")
            with open(debug_path, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(debug_path, 0o600)
            print(f"Applications response saved to {debug_path}")

        applications = []
        # Prepare CSV data collection
        csv_rows = []

        # Adjust the following path as needed based on actual API response structure
        if data.get("applications"):
            # Build CSV header based on whether server info is included
            csv_header = ["id", "application_name", "app_is_licensed_assess"]
            if include_protect_server_info:
                csv_header.extend(["server_name", "server_id", "protect_license_enabled"])

            app_list = data["applications"]
            for app in app_list:
                app_id = app.get("app_id")
                name = app.get("name")

                if app_id and name:
                    applications.append(Application(app_id, name))

                    license_level = "N/A"  # Default value
                    server_info = []  # Store server information

                    # Process all links for this application
                    for link in app.get("links", []):
                        # Get license information
                        if link.get("rel") == "license":
                            getLink_response = getLink(session, headers, params, link.get("href"), contrast_url)
                            if getLink_response.status_code == 200:
                                license_data = getLink_response.json()
                                license_level = license_data.get('license', {}).get('level', 'N/A')

                        # Get server information if requested
                        if include_protect_server_info and link.get("rel") == "servers":
                            getServer_response = getLink(session, headers, params, link.get("href"), contrast_url)
                            if getServer_response.status_code == 200:
                                server_data = getServer_response.json()
                                # Collect all servers for this application
                                for server in server_data.get("servers", []):
                                    server_info.append({
                                        'name': server.get("name", "N/A"),
                                        'id': server.get("server_id", "N/A"),
                                        'defend': server.get("defend", "N/A")
                                    })

                    # Build CSV rows
                    if include_protect_server_info:
                        if server_info:
                            # If there are multiple servers, create separate rows for each
                            for server in server_info:
                                csv_row = [app_id, name, license_level, server['name'], server['id'], server['defend']]
                                csv_rows.append(csv_row)
                        else:
                            # No servers found for this application
                            csv_row = [app_id, name, license_level, "No Servers", "N/A", "N/A"]
                            csv_rows.append(csv_row)
                    else:
                        csv_row = [app_id, name, license_level]
                        csv_rows.append(csv_row)

            # Write all data to CSV file
            with open("apps_and_servers.csv", "w", newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([safe_csv_cell(v) for v in csv_header])  # Write header row
                for row in csv_rows:
                    writer.writerow([safe_csv_cell(v) for v in row])

            print(f"CSV file 'apps_and_servers.csv' created with {len(csv_rows)} data rows")
            print("CSV Header:", ",".join(csv_header))
            print(f"Sample data rows written: {min(3, len(csv_rows))}")

        else:
            print("No applications found in response.")
            return
    else:
        status = response.status_code if response is not None else "n/a"
        print(f"Failed to get applications. Status code: {status}")
        print(f"Request failed: HTTP {status}")

if __name__ == "__main__":
    main()