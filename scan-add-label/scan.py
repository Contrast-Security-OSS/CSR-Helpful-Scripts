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


# Note: headers are built inside main() once credentials are loaded. No
# module-level header dict, which previously held an empty Authorization
# value that could leak out before credentials were confirmed.

params = {
    "expand": ["apps", "vulns"]
}

def getApplications(headers, params, org_id, contrast_url):
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    response = _SESSION.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    return response

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


def _parse_args():
    parser = argparse.ArgumentParser(description="Tag SAST scan projects in Contrast.")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full response bodies on error. Off by default.",
    )
    return parser.parse_args()


def main():
    args = _parse_args()

    # Read credentials from .creds file (defaults only; prompts override below)
    creds = read_creds_file()
    contrast_url = creds.get("CONTRAST_URL", "")
    org_id = creds.get("ORG_ID", "")
    username = creds.get("USERNAME", "")
    api_key = creds.get("API_KEY", "")
    service_key = creds.get("SERVICE_KEY", "")

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

    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    headers = {
        "Accept": "application/json",
        "API-Key": api_key,
        "Authorization": f"Basic {auth_b64}",
    }

    response = getProjects(headers, params, org_id, contrast_url)
    if response.status_code == 200:
        data = response.json()

        # Loop through all projects and print their id
        projects = data.get("content", [])
        for project in projects:
            print(project.get("id"))
            getProject_response = getProject(headers, params, org_id, project.get("id"), contrast_url)
            if getProject_response.status_code == 200:
                project_data = getProject_response.json()
                print(f"Project ID: {project_data.get('id')}, Name: {project_data.get('name')}")
                print(project_data)

                getScans_response = getScans(headers, params, org_id, project_data.get("id"), contrast_url)
                if getScans_response.status_code == 200:
                    scans_data = getScans_response.json()
                    print(f"Scans for Project ID {project_data.get('id')}:")
                    for scan in scans_data.get("content", []):
                        print(f"Scan ID: {scan.get('id')}, Status: {scan.get('status')}")
                        print(scans_data)

                        scan_data = getScan(headers, params, org_id, project_data.get("id"), scan.get("id"), contrast_url)
                        if scan_data.status_code == 200:
                            scan_details = scan_data.json()
                            print(f"Scan Details for ID {scan.get('id')}:")
                            print(scan_details)

                            print("Adding tags to scan project...")
                            try:
                                body = read_json_file("scan-add-label/tags.json")
                                tag_response = putTagForScanProject(headers, params, org_id, project_data.get("id"), json.loads(body), contrast_url)
                                if tag_response.status_code >= 400:
                                    print(f"Request failed: HTTP {tag_response.status_code}")
                                    if args.debug:
                                        print(tag_response.text)
                                else:
                                    print(f"Tag response: {tag_response.status_code}")
                            except FileNotFoundError:
                                print("Error: 'tags.json' file not found. Please ensure it exists in the script directory.")
                        else:
                            print(f"Request failed: HTTP {scan_data.status_code}")
                            if args.debug:
                                print(scan_data.text)

                else:
                    print(f"Request failed: HTTP {getScans_response.status_code}")
                    if args.debug:
                        print(getScans_response.text)
            else:
                print(f"Request failed: HTTP {getProject_response.status_code}")
                if args.debug:
                    print(getProject_response.text)
    else:
        print(f"Request failed: HTTP {response.status_code}")
        if args.debug:
            print(response.text)

if __name__ == "__main__":
    main()
