import requests
import base64
import datetime
import getpass
import json

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

def getApplications(headers, params, org_id):
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    response = requests.get(url, headers=headers, params=params)
    return response

def getVulnerabilities(headers, params, org_id, app_id, vuln_post_data):
    url = f"{contrast_url}/api/v4/aiml-remediation/organizations/{org_id}/applications/{app_id}/prompt-details"
    print(f"URL: {url}")
    response = requests.post(url, headers=headers, params=params, json=vuln_post_data)
    return response

def getRoutes(headers, params, org_id, app_id):
    url = f"{contrast_url}/api/ng/{org_id}/applications/{app_id}/route"
    response = requests.get(url, headers=headers, params=params)
    return response

def getServers(headers, params, org_id):
    url = f"{contrast_url}/api/ng/{org_id}/servers"
    response = requests.get(url, headers=headers, params=params)
    return response

def putToggleServerProtect(headers, params, org_id, server_id):
    url = f"{contrast_url}/api/ng/{org_id}/servers/{server_id}/defend"
    response = requests.put(url, headers=headers, params=params)
    return response

def read_json_file(filename):
    with open(filename, "r") as f:
        return f.read()

def main():
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

    
    body = read_json_file("prompt-details_post_body.json")
    vulns_response = getVulnerabilities(headers, params, org_id, app_id, json.loads(body))

    if vulns_response.status_code == 200:
        vulns_data = vulns_response.json()
        print(json.dumps(vulns_data, indent=4))
    else:
        print(f"Error fetching vulnerabilities: {vulns_response.status_code} - {vulns_response.text}")
                        

if __name__ == "__main__":
    main()