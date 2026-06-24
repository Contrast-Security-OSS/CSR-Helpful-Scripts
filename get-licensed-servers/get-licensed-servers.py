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

params = {
    "expand": ["apps", "vulns"]
}

def getServers(session, headers, params, org_id, contrast_url):
    url = f"{contrast_url}/api/ng/{org_id}/servers"
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

    response = getServers(session, headers, params, org_id, contrast_url)
    if response.status_code == 200:
        data = response.json()
        if args.debug_dir:
            debug_dir = os.path.expanduser(args.debug_dir)
            os.makedirs(debug_dir, exist_ok=True, mode=0o700)
            debug_path = os.path.join(debug_dir, "output.json")
            with open(debug_path, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(debug_path, 0o600)
            print(f"Servers response saved to {debug_path}")

        # Adjust the following path as needed based on actual API response structure
        if data.get("servers"):
            print(data.get("servers"))
            server_list = data["servers"]
            print(f"Total Servers: {len(server_list)}")
            for server in server_list:
                print(f"Server: " + server.get("name", "N/A") + " ID: " + str(server.get("id", "N/A")) + " Protect License Enabled: " + str(server.get("defend", "N/A")))
        else:
            print("No servers found in response.")
            return
    else:
        print(f"Request failed: HTTP {response.status_code}")

if __name__ == "__main__":
    main()