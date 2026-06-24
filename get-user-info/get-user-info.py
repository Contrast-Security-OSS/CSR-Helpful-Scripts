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

# Default per-request timeout (connect, read) seconds.
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

def getUsers(session, headers, params, org_id, contrast_url):
    """Fetch all users from the Contrast API"""
    url = f"{contrast_url}/api/ng/{org_id}/users"
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
    parser = argparse.ArgumentParser(description="Fetch user info from Contrast API.")
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

    # Fetch all users from the API
    response = getUsers(session, headers, params, org_id, contrast_url)
    if response.status_code == 200:  # HTTP 200 means success
        data = response.json()  # Parse JSON response into Python dict
        # Optionally save the response for debugging.
        _write_debug_json(args.debug_dir, "output.json", data)

    else:
        # Display error if API call failed (non-200 status code)
        print(f"Request failed: HTTP {response.status_code}")
        if args.debug:
            print(response.text)

# Only run main() if this script is executed directly (not imported)
if __name__ == "__main__":
    main()
