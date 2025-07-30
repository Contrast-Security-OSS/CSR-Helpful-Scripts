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

headers = {
    "Accept": "application/json"
}
params = {
    "expand": ["apps", "vulns"]
}



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

    #list of servers to ensure I don't just disable/enable all servers.  MODIFY THIS LIST OR PULL IN YOUR OWN LIST
    servers_list = [90926, 90086, 90001]

    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    headers["Authorization"] = f"Basic {auth_b64}"
    headers["API-Key"] = api_key

    response = getServers(headers, params, org_id)
    if response.status_code == 200:
        data = response.json()
        with open("output.json", "w") as f:
            json.dump(data, f, indent=2)
        print("Servers response saved to output.json")

        servers = []
        # Adjust the following path as needed based on actual API response structure
        if data.get("servers"):
            server_list = data["servers"]
            for server in server_list:
                server_id = server.get("server_id")
                if server_id in servers_list:
                    # this toggles the server protect feature.
                    putToggleServerProtect(headers, params, org_id, server_id)

        else:
            print("No servers found in response.")
            return

    else:
        print(f"Error: {response.status_code} - {response.text}")

if __name__ == "__main__":
    main()