# SPDX-License-Identifier: Apache-2.0
import argparse
import requests
import base64
import getpass
import json
import sys
import os

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

# Make the contrast_security helpers importable.
_api_client_dir = os.path.join(parent_dir, "contrast-security-api-client")
if _api_client_dir not in sys.path:
    sys.path.insert(0, _api_client_dir)

try:
    from contrast_security.utils import sanitize_filename
except ImportError:
    def sanitize_filename(filename):
        import re
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename or '')
        filename = filename.strip(' .')
        return filename or 'unnamed'


REQUEST_TIMEOUT = (10, 60)


def _make_session():
    s = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
        allowed_methods=frozenset(
            ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        ),
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s


_SESSION = _make_session()


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
    "expand": ["apps", "vulns"]
}

def getApplications(headers, params, org_id, offset=0, limit=50):
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    paged_params = dict(params)
    paged_params["offset"] = offset
    paged_params["limit"] = limit
    response = _SESSION.get(url, headers=headers, params=paged_params, timeout=REQUEST_TIMEOUT)
    return response


def getAllApplications(headers, params, org_id, limit=50):
    """Fetch all applications across paginated /applications responses."""
    all_apps = []
    offset = 0
    while True:
        response = getApplications(headers, params, org_id, offset=offset, limit=limit)
        if response.status_code != 200:
            return response, all_apps
        data = response.json()
        batch = data.get("applications", []) or []
        all_apps.extend(batch)
        if len(batch) < limit:
            return response, all_apps
        offset += limit


def getPolicies(headers, params, org_id, app_id):
    url = f"{contrast_url}/api/ng/{org_id}/applications/{app_id}/exclusions"
    response = _SESSION.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    return response

def read_json_file(filename):
    with open(filename, "r") as f:
        return f.read()

def postNewExclusion(headers, params, org_id, app_id, exclusion):
    url = f"{contrast_url}/api/ng/{org_id}/applications/{app_id}/exclusions"
    response = _SESSION.post(url, headers=headers, params=params, json=exclusion, timeout=REQUEST_TIMEOUT)
    return response


def _write_debug_json(debug_dir, filename, data):
    """Write JSON to debug_dir/filename with restrictive permissions.

    No-op when debug_dir is falsy.
    """
    if not debug_dir:
        return
    target_dir = os.path.expanduser(debug_dir)
    os.makedirs(target_dir, mode=0o700, exist_ok=True)
    safe_name = sanitize_filename(filename)
    target_path = os.path.join(target_dir, safe_name)
    fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)


def _parse_args():
    parser = argparse.ArgumentParser(description="Populate exclusion policies across applications.")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full response bodies on error. Off by default.",
    )
    parser.add_argument(
        "--debug-dir",
        default=None,
        help=(
            "Directory for debug JSON dumps. When unset, no debug files are written. "
            "Files are written with mode 0o600 in a directory with mode 0o700."
        ),
    )
    return parser.parse_args()


def main():
    args = _parse_args()

    global contrast_url, org_id, username, api_key, service_key

    msg = f"Enter your Contrast URL (blank will use default \'{contrast_url}\'): "
    contrast_url_input = input(msg)
    if contrast_url_input.strip():
        contrast_url = contrast_url_input
    else:
        while not contrast_url_input.strip() and not contrast_url.strip():
            print("Contrast URL cannot be blank.")
            contrast_url_input = input(msg)
            contrast_url = contrast_url_input

    msg = f"Enter your Organization ID (blank will use default \'{org_id}\'): "
    org_id_input = input(msg)
    if org_id_input.strip():
        org_id = org_id_input
    else:
        while not org_id_input.strip() and not org_id.strip():
            print("Organization ID cannot be blank.")
            org_id_input = input(msg)
            org_id = org_id_input

    msg = f"Enter your username (blank will use default \'{username}\'): "
    username_input = input(msg)
    if username_input.strip():
        username = username_input
    else:
        while not username_input.strip() and not username.strip():
            print("Username cannot be blank.")
            username_input = input(msg)
            username = username_input

    msg = f"Enter your API key (blank will use default \'****************************\'): "
    api_key_input = getpass.getpass(msg)
    if api_key_input.strip():
        api_key = api_key_input
    else:
        while not api_key_input.strip() and not api_key.strip():
            print("API key cannot be blank.")
            api_key_input = getpass.getpass(msg)
            api_key = api_key_input

    msg = f"Enter your service key (blank will use default \'************\'): "
    service_key_input = getpass.getpass(msg)
    if service_key_input.strip():
        service_key = service_key_input
    else:
        while not service_key_input.strip() and not service_key.strip():

            print("Service key cannot be blank.")
            service_key_input = getpass.getpass(msg)
            service_key = service_key_input

    # Debug output
    print("Adding Policy exclusions to all applications in organization.")

    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    headers["Authorization"] = f"Basic {auth_b64}"
    headers["API-Key"] = api_key

    response, all_apps_paged = getAllApplications(headers, params, org_id)
    if response.status_code == 200:
        data = {"applications": all_apps_paged}
        _write_debug_json(args.debug_dir, "applications.json", data)

        applications = []
        if data.get("applications"):
            app_list = data["applications"]
            for app in app_list:
                app_id = app.get("app_id")
                name = app.get("name")
                if app_id and name:
                    applications.append(Application(app_id, name))
        else:
            print("No applications found in response.")
            return

        policies_results = {}
        for app in applications:
            policy_response = getPolicies(headers, params, org_id, app.app_id)
            if policy_response.status_code == 200:
                policy_json = policy_response.json()
                policies_results[app.app_id] = policy_json
                # Write each app_id's policies to a separate file (gated)
                safe_name = sanitize_filename(app.name)
                filename = f"{safe_name}-policies.json"
                _write_debug_json(args.debug_dir, filename, policy_json)
                if args.debug_dir:
                    print(f"Policies for app_id {app.app_id} ({app.name}) saved to {filename}")

                body = read_json_file("exclusion_body.json")
                #postNewExclusion(headers, params, org_id, app.app_id, json.loads(body))
            else:
                print(f"Request failed for app_id {app.app_id}: HTTP {policy_response.status_code}")
                if args.debug:
                    print(policy_response.text)

        _write_debug_json(args.debug_dir, "policies_output.json", policies_results)
    else:
        print(f"Request failed: HTTP {response.status_code}")
        if args.debug:
            print(response.text)

if __name__ == "__main__":
    main()
