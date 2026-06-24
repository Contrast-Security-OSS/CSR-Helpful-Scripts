import requests
import base64
import getpass
import json
import csv  # Add csv import for proper CSV handling

include_protect_server_info = True

def getAgentVersions(headers, params, org_id):
    Auth_token = headers.get("Authorization", "")
    headers["Authorization"] = f"Basic {Auth_token}"
    url = f"{contrast_url}/api/ng/{org_id}/agents/versions"
    response = requests.get(url, headers=headers, params=params)
    return response

def getAgents(headers, params, org_id):
    # Remove /Contrast suffix if present in the base URL for v4 API
    
    base_url = contrast_url.rstrip('/').replace('/Contrast', '')
    url = f"{base_url}/api/v4/organizations/{org_id}/agents?sort=lastActive,desc&page=0&size=10"
    response = requests.get(url, headers=headers, params=params)
    return response

def get_agent_config(headers, org_id, agent_id, app_id):
    """Get the effective configuration for a specific agent"""
    base_url = contrast_url.rstrip('/').replace('/Contrast', '')
    url = f"{base_url}/api/v4/organizations/{org_id}/agents/{agent_id}/applications/{app_id}/effective-config"
    response = requests.get(url, headers=headers)
    return response

def read_creds_file(filename="../.creds"):
    """Read credentials from a .creds file"""
    creds = {}
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()  # Remove whitespace from beginning and end of line
                if line and not line.startswith("#"):  # Skip empty lines and comments
                    key, value = line.split("=", 1)  # Split on first = only
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
    response = requests.get(url, headers=headers, params=params)
    return response

def getLink(headers, params, link):
    url = f"{contrast_url}/api{link}"
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
    headers["Authorization"] = f"{auth_b64}"
    headers["API-Key"] = api_key

    resp2 = getAgentVersions(headers, params, org_id)
    print(f"Agent Versions response status code: {resp2.status_code}")
    print(resp2.text)

    response = getAgents(headers, params, org_id)
    print(f"Agents response status code: {response.status_code}")

    if response.status_code == 200:
        data = response.json()
        with open("output.json", "w") as f:
            json.dump(data, f, indent=2)
        print("Applications response saved to output.json")

        agents = []
        # Prepare CSV data collection
        csv_rows = []
        
        # The v4 API returns agents in a "content" array
        if data.get("content"):
            agents = data.get("content")
            print(f"\nFound {len(agents)} agents:\n")
            
            for agent in agents:
                full_agent_id = agent.get('id')
                
                # Split the agent ID - format is "app_id:agent_id"
                if ':' in full_agent_id:
                    app_id, agent_id = full_agent_id.split(':', 1)
                else:
                    print(f"Warning: Could not parse agent ID: {full_agent_id}")
                    continue
                
                print(f"Agent ID: {full_agent_id}")
                print(f"  App ID: {app_id}")
                print(f"  Agent Instance ID: {agent_id}")
                print(f"  Application: {agent.get('applicationName')}")
                print(f"  Server: {agent.get('serverName')}")
                print(f"  Language: {agent.get('language')}")
                print(f"  Version: {agent.get('displayVersion')}")
                print(f"  Status: {agent.get('status')}")
                print(f"  Environment: {agent.get('environment')}")
                print(f"  Last Active: {agent.get('lastActive')}")
                print(f"  Hostname: {agent.get('hostname')}")
                
                # Add server inventory details if available
                if agent.get('serverInventory'):
                    inventory = agent.get('serverInventory')
                    print(f"  OS: {inventory.get('operatingSystem')}")
                    print(f"  Runtime: {inventory.get('runtimeVersion')}")
                    print(f"  Docker: {inventory.get('isDocker')}, Kubernetes: {inventory.get('isKubernetes')}")
                
                # Get agent configuration
                config_response = get_agent_config(headers, org_id, agent_id, app_id)
                if config_response.status_code == 200:
                    config_data = config_response.json()
                    print(f"  Config retrieved successfully")
                    print(f"  Effective Config:")
                    
                    # Display all configuration settings
                    if isinstance(config_data, dict):
                        for key, value in config_data.items():
                            # Handle nested dictionaries
                            if isinstance(value, dict):
                                print(f"    {key}:")
                                for sub_key, sub_value in value.items():
                                    print(f"      {sub_key}: {sub_value}")
                            elif isinstance(value, list):
                                print(f"    {key}: {value}")
                            else:
                                print(f"    {key}: {value}")
                else:
                    print(f"  Config retrieval failed: {config_response.status_code}")
                
                print()  # Blank line between agents
        else:
            print("No agents found in response.")
            return

if __name__ == "__main__":
    main()