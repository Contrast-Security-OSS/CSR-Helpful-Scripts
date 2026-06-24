import base64
import getpass


def read_creds_file(filename=".creds"):
    """Read credentials from a .creds file"""
    creds = {}
    
    # Try current directory first
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    creds[key] = value
        return creds
    except FileNotFoundError:
        pass
    
    # If not found in current directory, try parent directory
    try:
        parent_filename = f"../{filename}"
        with open(parent_filename, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    creds[key] = value
        return creds
    except FileNotFoundError:
        print(f"Warning: {filename} file not found in current directory or parent directory. Please input values.")
    
    return creds


def get_credentials():
    """
    Collect Contrast Security credentials from user input with .creds file defaults.
    Returns a dictionary containing all credentials and configured headers.
    """
    # Read credentials from .creds file
    creds = read_creds_file()

    # Set the default values for re-using within your organization from .creds file
    contrast_url = creds.get("CONTRAST_URL", "")
    org_id = creds.get("ORG_ID", "")
    username = creds.get("USERNAME", "")
    api_key = creds.get("API_KEY", "")
    service_key = creds.get("SERVICE_KEY", "")
    app_id = creds.get("APP_ID", "")

    # Prompt user for Contrast URL, use default from .creds if blank
    msg = f"Enter your Contrast URL (blank will use default '{contrast_url}'): "
    contrast_url_input = input(msg)
    if contrast_url_input.strip():
        contrast_url = contrast_url_input
    else:
        while not contrast_url_input.strip() and not contrast_url.strip():
            print("Contrast URL cannot be blank.")
            contrast_url_input = input(msg)
            contrast_url = contrast_url_input

    # Prompt user for Organization ID, use default from .creds if blank
    msg = f"Enter your Organization ID (blank will use default '{org_id}'): "
    org_id_input = input(msg)
    if org_id_input.strip():
        org_id = org_id_input
    else:
        while not org_id_input.strip() and not org_id.strip():
            print("Organization ID cannot be blank.")
            org_id_input = input(msg)
            org_id = org_id_input

    # Prompt user for username, use default from .creds if blank
    msg = f"Enter your username (blank will use default '{username}'): "
    username_input = input(msg)
    if username_input.strip():
        username = username_input
    else:
        while not username_input.strip() and not username.strip():
            print("Username cannot be blank.")
            username_input = input(msg)
            username = username_input

    # Prompt user for API key (hidden input), use default from .creds if blank
    msg = f"Enter your API key (blank will use default '****************************'): "
    api_key_input = getpass.getpass(msg)
    if api_key_input.strip():
        api_key = api_key_input
    else:
        while not api_key_input.strip() and not api_key.strip():
            print("API key cannot be blank.")
            api_key_input = getpass.getpass(msg)
            api_key = api_key_input

    # Prompt user for service key (hidden input), use default from .creds if blank
    msg = f"Enter your service key (blank will use default '************'): "
    service_key_input = getpass.getpass(msg)
    if service_key_input.strip():
        service_key = service_key_input
    else:
        while not service_key_input.strip() and not service_key.strip():
            print("Service key cannot be blank.")
            service_key_input = getpass.getpass(msg)
            service_key = service_key_input

    # Create Basic Authentication header with encoded credentials
    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()

    # Set up standard headers
    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {auth_b64}",
        "API-Key": api_key
    }

    # Set up PUT headers (used by some scripts)
    put_headers = {
        "Accept": "application/json, text/plain, */*",
        "Authorization": f"Basic {auth_b64}",
        "API-Key": api_key
    }

    # Return all credentials and headers
    return {
        "contrast_url": contrast_url,
        "org_id": org_id,
        "username": username,
        "api_key": api_key,
        "service_key": service_key,
        "app_id": app_id,
        "headers": headers,
        "put_headers": put_headers
    }