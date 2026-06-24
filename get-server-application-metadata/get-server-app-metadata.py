# SPDX-License-Identifier: Apache-2.0
import requests
import base64
import getpass
import json
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
import csv

from contrast_security.utils import safe_csv_cell

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

def getApplications(session, headers, params, org_id):
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    response = session.get(url, headers=headers, params=params, timeout=(10, 60))
    return response

def getServers(session, headers, servers_href):
    url = f"{contrast_url}/api{servers_href}"
    response = session.get(url, headers=headers, timeout=(10, 60))
    return response

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

# Read credentials from .creds file
creds = read_creds_file()

# Set the default for re-using within your organization.
contrast_url = creds.get("CONTRAST_URL", "")
org_id = creds.get("ORG_ID", "")
username = creds.get("USERNAME", "")
api_key = creds.get("API_KEY", "")
service_key = creds.get("SERVICE_KEY", "")
app_id = creds.get("APP_ID", "")

headers = {
    "Accept": "application/json"
}
params = {
    "expand": ["apps", "vulns", "metadata"]
}

def main():
    global contrast_url, org_id, username, api_key, service_key

    parser = argparse.ArgumentParser()
    parser.add_argument("--debug-dir", default=None, help="Optional directory for debug JSON dumps (e.g. ~/.contrast-csr/)")
    args = parser.parse_args()

    session = _make_session()

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

    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    headers["Authorization"] = f"Basic {auth_b64}"
    headers["API-Key"] = api_key

    response = getApplications(session, headers, params, org_id)
    if response.status_code == 200:
        data = response.json()
        if args.debug_dir:
            debug_dir = os.path.expanduser(args.debug_dir)
            os.makedirs(debug_dir, exist_ok=True, mode=0o700)
            debug_path = os.path.join(debug_dir, "output.json")
            with open(debug_path, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(debug_path, 0o600)
            print(f"Applications response saved to {debug_path}")

        # List to collect CSV data
        csv_data = []

        if data.get("applications"):
            application_list = data["applications"]
            print(f"Total Applications: {len(application_list)}")
            
            for app in application_list:
                app_name = app.get("name", "N/A")
                app_id = app.get("app_id", "N/A")
                metadata_entities = app.get("metadataEntities", [])
                
                print(f"\nApplication: {app_name} (ID: {app_id})")
                
                # Output metadata entities
                if metadata_entities:
                    print(f"  Metadata Entities: {len(metadata_entities)} found")
                else:
                    print(f"  Metadata Entities: None")
                
                # Get the links array from the application
                links = app.get("links", [])
                
                # Find the servers link
                servers_href = None
                for link in links:
                    if link.get("rel") == "servers":
                        servers_href = link.get("href")
                        break
                
                if servers_href:
                    servers_response = getServers(session, headers, servers_href)
                    
                    if servers_response.status_code == 200:
                        servers_data = servers_response.json()
                        servers = servers_data.get("servers", [])
                        print(f"  Total Servers: {len(servers)}")
                        
                        if servers:
                            for server in servers:
                                server_name = server.get("name", "N/A")
                                server_id = server.get("server_id", "N/A")
                                print(f"    - Server: {server_name} (ID: {server_id})")
                                
                                # Add rows to CSV for each metadata entity
                                if metadata_entities:
                                    for entity in metadata_entities:
                                        field_name = entity.get("fieldName", "N/A")
                                        field_value = entity.get("fieldValue", "N/A")
                                        csv_data.append({
                                            "server_name": server_name,
                                            "server_id": server_id,
                                            "application_name": app_name,
                                            "application_id": app_id,
                                            "metadata_field_name": field_name,
                                            "metadata_field_value": field_value
                                        })
                                else:
                                    # If no metadata, still add a row with the server and app
                                    csv_data.append({
                                        "server_name": server_name,
                                        "server_id": server_id,
                                        "application_name": app_name,
                                        "application_id": app_id,
                                        "metadata_field_name": "N/A",
                                        "metadata_field_value": "N/A"
                                    })
                        else:
                            # No servers found, but add application with metadata if exists
                            if metadata_entities:
                                for entity in metadata_entities:
                                    field_name = entity.get("fieldName", "N/A")
                                    field_value = entity.get("fieldValue", "N/A")
                                    csv_data.append({
                                        "server_name": "N/A",
                                        "server_id": "N/A",
                                        "application_name": app_name,
                                        "application_id": app_id,
                                        "metadata_field_name": field_name,
                                        "metadata_field_value": field_value
                                    })
                            else:
                                # No servers and no metadata
                                csv_data.append({
                                    "server_name": "N/A",
                                    "server_id": "N/A",
                                    "application_name": app_name,
                                    "application_id": app_id,
                                    "metadata_field_name": "N/A",
                                    "metadata_field_value": "N/A"
                                })
                    else:
                        print(f"  Error fetching servers: {servers_response.status_code}")
                        # Add application with metadata even if server fetch fails
                        if metadata_entities:
                            for entity in metadata_entities:
                                field_name = entity.get("fieldName", "N/A")
                                field_value = entity.get("fieldValue", "N/A")
                                csv_data.append({
                                    "server_name": "N/A",
                                    "server_id": "N/A",
                                    "application_name": app_name,
                                    "application_id": app_id,
                                    "metadata_field_name": field_name,
                                    "metadata_field_value": field_value
                                })
                else:
                    print("  No servers link found for this application")
                    # Add application with metadata even if no servers link
                    if metadata_entities:
                        for entity in metadata_entities:
                            field_name = entity.get("fieldName", "N/A")
                            field_value = entity.get("fieldValue", "N/A")
                            csv_data.append({
                                "server_name": "N/A",
                                "server_id": "N/A",
                                "application_name": app_name,
                                "application_id": app_id,
                                "metadata_field_name": field_name,
                                "metadata_field_value": field_value
                            })
                    else:
                        # No servers link and no metadata
                        csv_data.append({
                            "server_name": "N/A",
                            "server_id": "N/A",
                            "application_name": app_name,
                            "application_id": app_id,
                            "metadata_field_name": "N/A",
                            "metadata_field_value": "N/A"
                        })
            
            # Write CSV file
            if csv_data:
                with open("server_app_metadata.csv", "w", newline="") as csvfile:
                    fieldnames = ["server_name", "server_id", "application_name", "application_id", "metadata_field_name", "metadata_field_value"]
                    writer = csv.writer(csvfile)
                    writer.writerow([safe_csv_cell(v) for v in fieldnames])
                    for row in csv_data:
                        writer.writerow([safe_csv_cell(row.get(k, "")) for k in fieldnames])
                print(f"\nCSV file created: server_app_metadata.csv ({len(csv_data)} rows)")
            else:
                print("\nNo data to write to CSV file.")
        else:
            print("No applications found in response.")
            return
    else:
        print(f"Request failed: HTTP {response.status_code}")

if __name__ == "__main__":
    main()