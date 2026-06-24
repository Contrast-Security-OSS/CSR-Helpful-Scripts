# SPDX-License-Identifier: Apache-2.0
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import base64
import getpass
import json
import csv
from datetime import datetime
import sys
import os
import argparse

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

def getScanById(session, headers, params, org_id, project_id):
    url = f"{contrast_url}/api/v1/organizations/{org_id}/projects/{project_id}/scans"
    response = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    return response

def getProjects(session, headers, params, org_id, page_num=0, page_size=50):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/overview?page={page_num}&size={page_size}&archived=false"
    response = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    return response

def getProjectById(session, headers, params, org_id, project_id):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/{project_id}/overview"
    response = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    return response

def read_json_file(filename):
    with open(filename, "r") as f:
        return f.read()

def main():
    global contrast_url, org_id, username, api_key, service_key

    parser = argparse.ArgumentParser(description="Fetch SAST scan data from the Contrast API.")
    parser.add_argument("--debug-dir", default=None,
                        help="Optional directory for debug JSON dumps. When omitted, nothing is written to disk.")
    parser.add_argument("--debug", action="store_true",
                        help="Print full response body on error (default: status code only).")
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

    # Initialize variables for pagination
    all_csv_data = []  # Collect data from all pages
    page_num = 0
    page_size = 50
    total_records = 0

     # Prompt user for number of pages to fetch
    pages_input = input("How many pages of data would you like to return? (default: 5): ")
    if pages_input.strip() and pages_input.strip().isdigit():
        max_pages = int(pages_input.strip())
        
        if max_pages < 0:
            max_pages = abs(max_pages)
            print(f"Warning: Negative value converted to positive: {max_pages}")
        # Limit to maximum of 10,000 pages
        # feel free to set a maximum limit to avoid excessive data retrieval but this is an upper limit to ensure no overload
        if max_pages > 10000:
            max_pages = 10000
            print(f"Warning: Maximum limit of 10,000 pages applied.")
    else:
        max_pages = 5  # Default to 5 if no input or invalid input

    # Prompt user for output format
    output_format = input("What kind of output do you want? (csv/json/both, default: both): ").strip().lower()
    if output_format not in ['csv', 'json', 'both']:
        output_format = 'both'  # Default to both if invalid input

    output_remove_duplicates = input("Remove duplicate scan project entries in CSV output? (y/n, default: n): ").strip().lower()
    if output_remove_duplicates in ['y', 'yes', 'true']:
        output_remove_duplicates = 'y'
    else:
        output_remove_duplicates = 'n'

    print(f"Will fetch up to {max_pages} pages of data...")

    print(f"Output format selected: {output_format}")
    
    # Loop through pages until we reach the end or hit the 5-page limit
    while page_num < max_pages:  # Limit to 5 pages as requested
        print(f"Fetching page {page_num + 1}...")
        
        response = getProjects(session, headers, params, org_id, page_num, page_size)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract pagination info from the response
            is_last_page = data.get('last', True)
            current_page_elements = data.get('numberOfElements', 0)
            total_elements = data.get('totalElements', 0)
            total_pages = data.get('totalPages', 0)
            
            print(f"Page {page_num + 1}: {current_page_elements} records")
            print(f"Total elements across all pages: {total_elements}")
            print(f"Total pages available: {total_pages}")
            
            duplicate_name_checker = set()  # To track duplicates if needed

            # Extract project data for CSV from current page
            projects = data.get('content', [])
            
            for project in projects:
                if output_remove_duplicates == 'y':
                    if project.get('name', '') in duplicate_name_checker:
                        continue  # Skip duplicate entry
                    duplicate_name_checker.add(project.get('name', ''))

                all_csv_data.append({
                    'id': project.get('id', ''),
                    'organizationId': project.get('organizationId', ''),
                    'name': project.get('name', ''),
                    'archived': project.get('archived', ''),
                    'language': project.get('language', ''),
                    'critical': project.get('critical', 0),
                    'high': project.get('high', 0),
                    'medium': project.get('medium', 0),
                    'low': project.get('low', 0),
                    'note': project.get('note', 0),
                    'lastScanTime': project.get('lastScanTime', ''),
                    'completedScans': project.get('completedScans', 0),
                    'lastScanId': project.get('lastScanId', ''),
                    'createdBy': project.get('createdBy', ''),
                    'createdTime': project.get('createdTime', ''),
                    'vulnerableLanguages': str(project.get('vulnerableLanguages', [])),
                    'parentId': project.get('parentId', ''),
                    'branch': project.get('branch', ''),
                    'dynamicScoring': project.get('dynamicScoring', False),
                    'tags': str(project.get('tags', [])),
                    'metadata': str(project.get('metadata', {})),
                    'branches': str(project.get('branches', []))
                })
                # Fetch additional project details if needed
                proj_response = getProjectById(session, headers, params, org_id, project.get('id', ''))
                if proj_response.status_code == 200:
                    proj_data = proj_response.json()
                    # use for debugging: print(f"Project data for {project.get('name', 'Unknown')}: {json.dumps(proj_data, indent=2)}")
                    
                    # Extract additional scan data from project details
                    scan_data = {
                        'totalVulnerabilities': proj_data.get('totalVulnerabilities', 0),
                        'newVulnerabilities': proj_data.get('newVulnerabilities', 0),
                        'remediatedVulnerabilities': proj_data.get('remediatedVulnerabilities', 0),
                        'totalScans': proj_data.get('totalScans', 0),
                        'daysSinceLastScan': proj_data.get('daysSinceLastScan', 0),
                        'scan_creationTime': proj_data.get('creationTime', ''),
                        'scan_critical': proj_data.get('critical', 0),
                        'scan_high': proj_data.get('high', 0),
                        'scan_medium': proj_data.get('medium', 0),
                        'scan_low': proj_data.get('low', 0),
                        'scan_note': proj_data.get('note', 0),
                        'notAProblem': proj_data.get('notAProblem', 0)
                    }
                    
                    # Update the last entry in all_csv_data with the scan data
                    if all_csv_data:
                        all_csv_data[-1].update(scan_data)
                else:
                    # If project details call fails, add empty values to maintain consistent structure
                    scan_data = {
                        'totalVulnerabilities': 0,
                        'newVulnerabilities': 0,
                        'remediatedVulnerabilities': 0,
                        'totalScans': 0,
                        'daysSinceLastScan': 0,
                        'scan_creationTime': '',
                        'scan_critical': 0,
                        'scan_high': 0,
                        'scan_medium': 0,
                        'scan_low': 0,
                        'scan_note': 0,
                        'notAProblem': 0
                    }
                    if all_csv_data:
                        all_csv_data[-1].update(scan_data)
            
            total_records += len(projects)
            
            # Save the response from the first page for reference (gated behind --debug-dir).
            if page_num == 0 and output_format in ['json', 'both']:
                if args.debug_dir:
                    _write_debug_json(args.debug_dir, "output.json", data)
                    print(f"First page response saved to {os.path.join(os.path.expanduser(args.debug_dir), 'output.json')}")
            
            # Check if this was the last page or if we have no more data
            if is_last_page or current_page_elements == 0:
                print(f"Reached last page (page {page_num + 1})")
                break
                
            # Move to next page
            page_num += 1
            
        else:
            print(f"Request failed on page {page_num + 1}: HTTP {response.status_code}")
            if args.debug:
                print(response.text)
            break

    # Write collected data to files based on user selection
    if all_csv_data:
        # Write CSV file if requested
        if output_format in ['csv', 'both']:
            with open("output.csv", "w", newline='', encoding='utf-8') as csvfile:
                fieldnames = ['id', 'organizationId', 'name', 'archived', 'language', 'critical', 
                             'high', 'medium', 'low', 'note', 'lastScanTime', 'completedScans', 
                             'lastScanId', 'createdBy', 'createdTime', 'vulnerableLanguages', 
                             'parentId', 'branch', 'dynamicScoring', 'tags', 'metadata', 'branches',
                             'totalVulnerabilities', 'newVulnerabilities', 'remediatedVulnerabilities',
                             'totalScans', 'daysSinceLastScan', 'scan_creationTime', 'scan_critical',
                             'scan_high', 'scan_medium', 'scan_low', 'scan_note', 'notAProblem']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for row in all_csv_data:
                    writer.writerow(row)
            print(f"Data saved to output.csv with {len(all_csv_data)} records")
        
        # Write JSON file if requested (and not already written above)
        if output_format == 'json' and page_num > 0:
            # Create a comprehensive JSON output with all collected data
            json_output = {
                'totalRecords': total_records,
                'totalPages': page_num + 1,
                'projects': all_csv_data
            }
            with open("output.json", "w") as f:
                json.dump(json_output, f, indent=2)
            print(f"Data saved to output.json with {len(all_csv_data)} records")
        
        print(f"\nPagination complete!")
        print(f"Total pages processed: {page_num + 1}")
        print(f"Total records collected: {total_records}")
        print(f"Output format: {output_format}")
    else:
        print("No project data found across all pages")

if __name__ == "__main__":
    main()