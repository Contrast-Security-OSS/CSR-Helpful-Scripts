# SPDX-License-Identifier: Apache-2.0
"""
app-add-label

Adds tags/labels to applications in a Contrast organization.

WARNING: examples in specific_apps.csv must be synthetic, do not commit
customer data.
"""
import argparse
import csv
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
    from contrast_security.utils import safe_csv_cell, sanitize_filename  # noqa: F401
except ImportError:
    def sanitize_filename(filename):
        import re
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename or '')
        filename = filename.strip(' .')
        return filename or 'unnamed'

    def safe_csv_cell(value):
        if value is None:
            return ""
        text = value if isinstance(value, str) else str(value)
        if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + text
        return text


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

def read_specific_file(filename="specific_apps.csv"):
    """Read specific_apps file - format can be:
    - Just app_id (will use tags from tags.json)
    - app_id,tag1,tag2,tag3 (will use specific tags, no quotes)
    - app_id,"tag1","tag2" (will use specific tags, with double quotes)
    - app_id,'tag1','tag2' (will use specific tags, with single quotes)
    """
    print("Reading specific_apps file")
    apps = {}
    try:
        with open(filename, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                # Skip comment lines and empty lines
                first = row[0].strip()
                if not first or first.startswith("#"):
                    continue
                if len(row) >= 2:
                    app_id = first.strip('"').strip("'")
                    tags = [t.strip().strip('"').strip("'") for t in row[1:] if t.strip()]
                    apps[app_id] = tags
                    print(f"Loaded app_id: {app_id}, with specific tags: {tags}")
                else:
                    app_id = first.strip('"').strip("'")
                    apps[app_id] = []  # Empty list means use tags.json
                    print(f"Loaded app_id: {app_id}, will use tags from tags.json")
    except FileNotFoundError:
        print(f"Warning: {filename} file not found. Please input values.")
    return apps

params = {
    "expand": ["apps", "vulns"]
}

def getApplications(headers, params, org_id, contrast_url, offset=0, limit=50):
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    paged_params = dict(params)
    paged_params["offset"] = offset
    paged_params["limit"] = limit
    response = _SESSION.get(url, headers=headers, params=paged_params, timeout=REQUEST_TIMEOUT)
    return response


def getAllApplications(headers, params, org_id, contrast_url, limit=50):
    """Fetch all applications across paginated /applications responses."""
    all_apps = []
    offset = 0
    while True:
        response = getApplications(headers, params, org_id, contrast_url, offset=offset, limit=limit)
        if response.status_code != 200:
            return response, all_apps
        data = response.json()
        batch = data.get("applications", []) or []
        all_apps.extend(batch)
        # Stop when we got fewer than limit (last page) or none.
        if len(batch) < limit:
            return response, all_apps
        offset += limit

def getProjects(headers, params, org_id, contrast_url):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects"
    print(url)
    print(list(headers.keys()))
    response = _SESSION.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    return response

def getProject(headers, params, org_id, project_id, contrast_url):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/{project_id}"
    print(url)
    print(list(headers.keys()))
    response = _SESSION.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    return response

def getScans(headers, params, org_id, project_id, contrast_url):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/{project_id}/scans"
    print(url)
    print(list(headers.keys()))
    response = _SESSION.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    return response

def getScan(headers, params, org_id, project_id, scan_id, contrast_url):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/{project_id}/scans/{scan_id}"
    print(url)
    print(list(headers.keys()))
    response = _SESSION.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    return response

def putTagForScanProject(headers, params, org_id, app_id, tagJson, contrast_url):
    url = f"{contrast_url}/api/sast/organization/{org_id}/projects/tags"
    response = _SESSION.put(url, headers=headers, params=params, json=tagJson, timeout=REQUEST_TIMEOUT)
    return response

def putTagForApp(headers, params, org_id, app_id, tagJson, contrast_url):
    """Add tags to an application using the bulk tag API endpoint"""
    url = f"{contrast_url}/api/ng/{org_id}/tags/applications/bulk?expand=skip_links"
    response = _SESSION.put(url, headers=headers, json=tagJson, timeout=REQUEST_TIMEOUT)
    return response

def getPolicies(headers, params, org_id, app_id, contrast_url):
    url = f"{contrast_url}/api/ng/{org_id}/applications/{app_id}/exclusions"
    response = _SESSION.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    return response

def read_json_file(filename):
    with open(filename, "r") as f:
        return f.read()

def postNewExclusion(headers, params, org_id, app_id, exclusion, contrast_url):
    url = f"{contrast_url}/api/ng/{org_id}/applications/{app_id}/exclusions"
    response = _SESSION.post(url, headers=headers, params=params, json=exclusion, timeout=REQUEST_TIMEOUT)
    return response


def _write_debug_json(debug_dir, filename, data):
    """Write JSON to debug_dir/filename with restrictive permissions.

    No-op if debug_dir is falsy.
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
    parser = argparse.ArgumentParser(description="Add labels to Contrast applications.")
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

    # Get credentials using the shared module
    creds = get_credentials()
    contrast_url = creds["contrast_url"]
    org_id = creds["org_id"]
    headers = creds["headers"]
    put_headers = creds["put_headers"]

    response, all_apps_paged = getAllApplications(headers, params, org_id, contrast_url)
    if response.status_code == 200:
        data = {"applications": all_apps_paged}

        # Read tags JSON file
        try:
            body = read_json_file("tags.json")
        except FileNotFoundError:
            print("Error: 'tags.json' file not found. Please ensure it exists in the script directory.")
            return

        # Read specific apps CSV file
        apps = read_specific_file("specific_apps.csv")

        print("=========================================")
        print(apps)
        print("=========================================")

        # Get applications - either from CSV or from API response
        if not apps or len(apps) == 0:
            # No specific apps in CSV, process all applications from API response
            applications = data.get("applications", [])
            print("No specific apps found in CSV, will process all applications from API response")
        else:
            # Use specific apps from CSV file - filter API response to only include apps in CSV
            applications = []
            all_apps = data.get("applications", [])
            for app in all_apps:
                if app.get("app_id") in apps:
                    applications.append(app)
            print(f"Processing {len(applications)} specific applications from CSV file")

        print("Adding tags to applications...")

        # Process each application
        for app in applications:
            app_id = app.get("app_id")
            app_name = app.get("name", "Unknown")

            print(f"Processing application: {app_name} ({app_id})")

            # Parse the body JSON for each iteration
            tag_body = json.loads(body)

            # Assign the application ID to the body
            tag_body["applications_id"] = [app_id]

            # Assign tags - if CSV has specific tags for this app, overwrite tags.json; if CSV has empty array, keep tags.json
            if app_id in apps and apps[app_id]:
                # App has specific tags in CSV - overwrite tags from tags.json
                tag_body["tags"] = apps[app_id]
                print(f"Using specific tags from CSV: {apps[app_id]}")
            else:
                # App ID is in CSV but has no tags, or not in CSV - keep tags from tags.json
                print(f"Using tags from tags.json: {tag_body.get('tags', [])}")

            print(f"Tag body: {json.dumps(tag_body, indent=2)}")

            # Optional debug dump of the policy/tag body, gated by --debug-dir.
            safe_app_name = sanitize_filename(app_name)
            _write_debug_json(args.debug_dir, f"{safe_app_name}-policies.json", tag_body)

            # Send the tag update request
            tag_response = putTagForApp(headers, params, org_id, app_id, tag_body, contrast_url)
            if tag_response.status_code >= 400:
                print(f"Request failed: HTTP {tag_response.status_code}")
                if args.debug:
                    print(tag_response.text)
            else:
                print(f"Tag response: {tag_response.status_code}")

    else:
        print(f"Request failed: HTTP {response.status_code}")
        if args.debug:
            print(response.text)

if __name__ == "__main__":
    main()
