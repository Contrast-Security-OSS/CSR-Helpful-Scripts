import requests
import base64
import getpass
import json

class Application:
    def __init__(self, app_id, name):
        self.app_id = app_id
        self.name = name

# set the default for re-using within your organization.  example: https://blah.contrastsecurity.com/Contrast/
contrast_url = ""
# set the default for your organization ID, example: a234323b-23a3-333c-111e-1234561abc32
org_id = ""
# set the default for your username, example: firstname.lastname@domain.com
username = ""
# set the default for your API key, example: 8qut7ylK42ZUZiWB4UHg8SlcBeC5eKOc
api_key = ""  # never save this in a public repo as it's a secret/sensitive information
# set the default for your service key, example: J32NO12345ZYWUTV
service_key = "" # never save this in a public repo as it's a secret/sensitive information

authorization_key = ""

headers = {
    "Accept": "application/json",
    "API-Key": api_key,
    "Authorization": authorization_key
}

put_headers = {
    "Accept": "application/json, text/plain, */*",
    "API-Key": api_key,
    "Authorization": authorization_key
}
params = {
    "expand": ["apps", "vulns"]
}

def getApplications(headers, params, org_id):
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    response = requests.get(url, headers=headers, params=params)
    return response

def getProjects(headers, params, org_id):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects"
    print(url)
    print(headers)
    response = requests.get(url, headers=headers)
    return response

def getProject(headers, params, org_id, project_id):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/{project_id}"
    print(url)
    print(headers)
    response = requests.get(url, headers=headers)
    return response

def getScans(headers, params, org_id, project_id):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/{project_id}/scans"
    print(url)
    print(headers)
    response = requests.get(url, headers=headers)
    return response

def getScan(headers, params, org_id, project_id, scan_id):
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/{project_id}/scans/{scan_id}"
    print(url)
    print(headers)
    response = requests.get(url, headers=headers)
    return response

def putTagForScanProject(headers, params, org_id, app_id, tagJson):
    url = f"{contrast_url}/api/sast/organization/{org_id}/projects/tags"
    response = requests.put(url, headers=headers, params=params, json=tagJson)
    return response

def getPolicies(headers, params, org_id, app_id):
    url = f"{contrast_url}/api/ng/{org_id}/applications/{app_id}/exclusions"
    response = requests.get(url, headers=headers, params=params)
    return response

def read_json_file(filename):
    with open(filename, "r") as f:
        return f.read()

def postNewExclusion(headers, params, org_id, app_id, exclusion):
    url = f"{contrast_url}/api/ng/{org_id}/applications/{app_id}/exclusions"
    response = requests.post(url, headers=headers, params=params, json=exclusion)
    return response

def main():
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
    
    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    headers["Authorization"] = f"Basic {auth_b64}"
    headers["API-Key"] = api_key

    response = getProjects(headers, params, org_id)
    if response.status_code == 200:
        data = response.json()
        with open("output.json", "w") as f:
            json.dump(data, f, indent=2)
       
        # Loop through all projects and print their id
        # Adjust the key below if your JSON structure is different
        projects = data.get("content", [])
        for project in projects:
            print(project.get("id"))
            getProject_response = getProject(headers, params, org_id, project.get("id"))
            if getProject_response.status_code == 200:
                project_data = getProject_response.json()
                print(f"Project ID: {project_data.get('id')}, Name: {project_data.get('name')}")
                print(project_data)

                getScans_response = getScans(headers, params, org_id, project_data.get("id"))
                if getScans_response.status_code == 200:
                    scans_data = getScans_response.json()
                    print(f"Scans for Project ID {project_data.get('id')}:")
                    for scan in scans_data.get("content", []):
                        print(f"Scan ID: {scan.get('id')}, Status: {scan.get('status')}")
                        print(scans_data)

                        scan_data = getScan(headers, params, org_id, project_data.get("id"), scan.get("id"))
                        if scan_data.status_code == 200:
                            scan_details = scan_data.json()
                            print(f"Scan Details for ID {scan.get('id')}:")
                            print(scan_details)

                            #if (scan.get("id") == ""): #add in a scan id to filter on here if you want to test it out.
                            print("Adding tags to scan project...")
                            # Read the tags from the JSON file and add them to the scan project
                            # Adjust the path to your JSON file as needed
                            try:
                                body = read_json_file("scan-add-label/tags.json")
                                tag_response = putTagForScanProject(headers, params, org_id, project_data.get("id"), json.loads(body))
                                print(f"Tag response: {tag_response.status_code} - {tag_response.text}")
                            except FileNotFoundError:
                                print("Error: 'tags.json' file not found. Please ensure it exists in the script directory.")

                else:
                    print(f"Error fetching scans: {getScans_response.status_code} - {getScans_response.text}")
            else:
                print(f"Error fetching project details: {getProject_response.status_code} - {getProject_response.text}")
    else:
        print(f"Error: {response.status_code} - {response.text}")

if __name__ == "__main__":
    main()