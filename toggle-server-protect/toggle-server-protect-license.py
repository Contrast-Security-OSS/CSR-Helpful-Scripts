# SPDX-License-Identifier: Apache-2.0
import argparse
import datetime
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


REQUEST_TIMEOUT = (10, 60)

AUDIT_LOG_PATH = os.path.join(
    os.path.expanduser("~/.contrast-csr"), "toggle-audit.log"
)


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

def getServers(headers, params, org_id):
    url = f"{contrast_url}/api/ng/{org_id}/servers"
    response = _SESSION.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    return response


def _append_audit(server_id, server_name, status_code, status_text):
    """Append an audit record describing a toggle attempt.

    Each record is one JSON object per line for easy parsing.
    """
    audit_dir = os.path.dirname(AUDIT_LOG_PATH)
    os.makedirs(audit_dir, mode=0o700, exist_ok=True)
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "server_id": server_id,
        "server_name": server_name,
        "http_status": status_code,
        "status_text": status_text,
    }
    line = json.dumps(record) + "\n"
    # Open with restrictive mode if creating; append otherwise.
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(AUDIT_LOG_PATH, flags, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(line)


def putToggleServerProtect(headers, params, org_id, server_id, server_name=None, debug=False):
    url = f"{contrast_url}/api/ng/{org_id}/servers/{server_id}/defend"
    try:
        response = _SESSION.put(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        _append_audit(server_id, server_name, None, f"request_exception: {type(exc).__name__}")
        print(f"Request failed for server {server_id}: {type(exc).__name__}")
        return None

    status_code = response.status_code
    status_text = getattr(response, "reason", "") or ""
    _append_audit(server_id, server_name, status_code, status_text)

    if status_code >= 400:
        print(f"Request failed for server {server_id}: HTTP {status_code}")
        if debug:
            print(response.text)
    else:
        print(f"Toggle response for server {server_id}: HTTP {status_code}")
    return response

def read_json_file(filename):
    with open(filename, "r") as f:
        return f.read()


def _parse_server_ids(raw):
    """Parse a comma-separated string of server IDs into a list of ints."""
    if not raw:
        return []
    ids = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.append(int(part))
        except ValueError:
            raise SystemExit(f"Invalid --server-ids entry (not an integer): {part!r}")
    return ids


def _parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Toggle Contrast Protect license on a specific list of server IDs. "
            "All targeted IDs must be provided via --server-ids. There is no "
            "default list."
        )
    )
    parser.add_argument(
        "--server-ids",
        required=True,
        help="Comma-separated list of numeric server IDs to toggle (e.g. 1234,5678).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive confirmation. Required for unattended runs.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full response bodies on error. Off by default.",
    )
    return parser.parse_args()


def _confirm(server_id, server_name):
    name_display = server_name if server_name else "<unknown>"
    answer = input(f"Toggle protect on server {server_id} ({name_display})? [y/N] ").strip().lower()
    return answer == "y"


def main():
    args = _parse_args()

    servers_list = _parse_server_ids(args.server_ids)
    if not servers_list:
        raise SystemExit("--server-ids must contain at least one integer server ID.")

    global contrast_url, org_id, username, api_key, service_key

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

    response = getServers(headers, params, org_id)
    if response.status_code == 200:
        data = response.json()

        # Adjust the following path as needed based on actual API response structure
        if data.get("servers"):
            server_list = data["servers"]
            for server in server_list:
                server_id = server.get("server_id")
                server_name = server.get("name") or server.get("hostname")
                if server_id in servers_list:
                    if not args.yes and not _confirm(server_id, server_name):
                        print(f"Skipped server {server_id} (no explicit confirmation).")
                        _append_audit(server_id, server_name, None, "skipped_no_confirm")
                        continue
                    # This toggles the server protect feature.
                    putToggleServerProtect(headers, params, org_id, server_id, server_name=server_name, debug=args.debug)
        else:
            print("No servers found in response.")
            return
    else:
        print(f"Request failed: HTTP {response.status_code}")
        if args.debug:
            print(response.text)

if __name__ == "__main__":
    main()
