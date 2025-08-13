import requests
import base64
import datetime
import getpass
import json

class Application:
    def __init__(self, app_id, name):
        self.app_id = app_id
        self.name = name
        self.path = None
        self.language = None
        self.created = None
        self.status = None
        self.importance = None
        self.archived = None
        self.assess = None
        self.assessPending = None
        self.primary = None
        self.master = None
        self.notes = None
        self.roles = None
        self.tags = None
        self.parentApplicationId = None
        self.techs = None
        self.policies = None
        self.missingRequiredFields = None
        self.protect = None
        self.links = None
        self.last_seen = None
        self.last_reset = None
        self.size_shorthand = None
        self.size = None
        self.code_shorthand = None
        self.code = None
        self.override_url = None
        self.short_name = None
        self.importance_description = None
        self.total_modules = None
        self.first_seen = None
        self.onboarded_time = None
    def __str__(self):
        outputStr = f"(\n"
        if self.app_id is not None:
            outputStr += f"  app_id={self.app_id},\n"
        if self.name is not None:
            outputStr += f"  name={self.name},\n"
        if self.path is not None:
            outputStr += f"  path={self.path},\n"
        if self.language is not None:
            outputStr += f"  language={self.language},\n"
        if self.created is not None:
            outputStr += f"  created={self.created},\n"
        if self.status is not None:
            outputStr += f"  status={self.status},\n"
        if self.importance is not None:
            outputStr += f"  importance={self.importance},\n"
        if self.archived is not None:
            outputStr += f"  archived={self.archived},\n"
        if self.assess is not None:
            outputStr += f"  assess={self.assess},\n"
        if self.assessPending is not None:
            outputStr += f"  assessPending={self.assessPending},\n"
        if self.primary is not None:
            outputStr += f"  primary={self.primary},\n"
        if self.master is not None:
            outputStr += f"  master={self.master},\n"
        if self.notes is not None:
            outputStr += f"  notes={self.notes},\n"
        if self.roles is not None:
            outputStr += f"  roles={self.roles},\n"
        if self.tags is not None:
            outputStr += f"  tags={self.tags},\n"
        if self.parentApplicationId is not None:
            outputStr += f"  parentApplicationId={self.parentApplicationId},\n"
        if self.techs is not None:
            outputStr += f"  techs={self.techs},\n"
        if self.policies is not None:
            outputStr += f"  policies={self.policies},\n"
        if self.missingRequiredFields is not None:
            outputStr += f"  missingRequiredFields={self.missingRequiredFields},\n"
        if self.protect is not None:
            outputStr += f"  protect={self.protect},\n"
        if self.links is not None:
            outputStr += f"  links={self.links},\n"
        if self.last_seen is not None:
            outputStr += f"  last_seen={self.last_seen},\n"
        if self.last_reset is not None:
            outputStr += f"  last_reset={self.last_reset},\n"
        if self.size_shorthand is not None:
            outputStr += f"  size_shorthand={self.size_shorthand},\n"
        if self.size is not None:
            outputStr += f"  size={self.size},\n"
        if self.code_shorthand is not None:
            outputStr += f"  code_shorthand={self.code_shorthand},\n"
        if self.code is not None:
            outputStr += f"  code={self.code},\n"
        if self.override_url is not None:
            outputStr += f"  override_url={self.override_url},\n"
        if self.short_name is not None:
            outputStr += f"  short_name={self.short_name},\n"
        if self.importance_description is not None:
            outputStr += f"  importance_description={self.importance_description},\n"
        if self.total_modules is not None:
            outputStr += f"  total_modules={self.total_modules},\n"
        if self.first_seen is not None: 
            outputStr += f"  first_seen={self.first_seen},\n"
        if self.onboarded_time is not None:
            outputStr += f"  onboarded_time={self.onboarded_time}\n"
        outputStr += f")"
        return (outputStr)

class Route:
    def __init__(self):
        self.app = None
        self.signature = None
        self.servers = None
        self.environments = None
        self.vulnerabilities = None
        self.exercised = None
        self.discovered = None
        self.status = None
        self.route_hash = None
        self.route_hash_string = None
        self.servers_total = None
        self.critical_vulnerabilities = None
    def __str__(self):
        outputStr = f"(\n"
        if self.app is not None:
            outputStr += f"  app={self.app},\n"
        if self.signature is not None:
            outputStr += f"  signature={self.signature},\n"
        if self.servers is not None:
            outputStr += f"  servers={self.servers},\n"
        if self.environments is not None:
            outputStr += f"  environments={self.environments},\n"
        if self.vulnerabilities is not None:
            outputStr += f"  vulnerabilities={self.vulnerabilities},\n"
        if self.exercised is not None:
            outputStr += f"  exercised={self.exercised},\n"
        if self.discovered is not None:
            outputStr += f"  discovered={self.discovered},\n"
        if self.status is not None:
            outputStr += f"  status={self.status},\n"
        if self.route_hash is not None:
            outputStr += f"  route_hash={self.route_hash},\n"
        if self.route_hash_string is not None:
            outputStr += f"  route_hash_string={self.route_hash_string},\n"
        if self.servers_total is not None:
            outputStr += f"  servers_total={self.servers_total},\n"
        if self.critical_vulnerabilities is not None:
            outputStr += f"  critical_vulnerabilities={self.critical_vulnerabilities}\n"
        outputStr += f")"
        return (outputStr)

class Vulnerability:
    def __init__(self):
        self.uuid = None
        self.title = None
        self.ruleName = None
        self.visible = None
        self.severity = None
        self.defaultSeverity = None
        self.tags = None
        self.application = None
        self.lastDetected = None
        self.firstDetected = None
        self.status = None
        self.statusKeycode = None
        self.subStatus = None
        self.violations = None
        self.sessionMetadata = None
    def __str__(self):
        outputStr = f"(\n"
        if self.uuid is not None:
            outputStr += f"  uuid={self.uuid},\n"
        if self.title is not None:
            outputStr += f"  title={self.title},\n"
        if self.ruleName is not None:
            outputStr += f"  ruleName={self.ruleName},\n"
        if self.visible is not None:
            outputStr += f"  visible={self.visible},\n"
        if self.severity is not None:
            outputStr += f"  severity={self.severity},\n"
        if self.defaultSeverity is not None:
            outputStr += f"  defaultSeverity={self.defaultSeverity},\n"
        if self.tags is not None:
            outputStr += f"  tags={self.tags},\n"   
        if self.application is not None:
            outputStr += f"  application={self.application},\n"
        if self.lastDetected is not None:
            outputStr += f"  lastDetected={self.lastDetected},\n"
        if self.firstDetected is not None:
            outputStr += f"  firstDetected={self.firstDetected},\n"
        if self.status is not None:
            outputStr += f"  status={self.status},\n"
        if self.statusKeycode is not None:
            outputStr += f"  statusKeycode={self.statusKeycode},\n"
        if self.subStatus is not None:
            outputStr += f"  subStatus={self.subStatus},\n"
        if self.violations is not None:
            outputStr += f"  violations={self.violations},\n"
        if self.sessionMetadata is not None:
            outputStr += f"  sessionMetadata={self.sessionMetadata}\n"
        outputStr += f")"

        return (outputStr)

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
    url = f"{contrast_url}/api/ng/organizations/{org_id}/orgtraces/ui?expand=application&offset=0&limit=25&sort=-severity"
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

    response = getApplications(headers, params, org_id)
    if response.status_code == 200:
        data = response.json()
        with open("output.json", "w") as f:
            json.dump(data, f, indent=2)
        print("Applications response saved to output.json")

##### TODO, anything that is absolutely not needed, remove field so it doesn't hold in session memory.
        applications = []
        # Adjust the following path as needed based on actual API response structure
        if data.get("applications"):
            app_list = data["applications"]
            for app in app_list:
                app_id = app.get("app_id")
                app_name = app.get("name")
                if app_id and app_name:
                    application = Application(app_id, app_name)
                    # Populate all other fields from the JSON
                    application.language = app.get("language")
                    application.path = app.get("path")
                    application.created = app.get("created")
                    if application.created:
                        application.created = datetime.datetime.fromtimestamp(application.created / 1000).strftime('%m/%d/%Y %H:%M')
                    application.status = app.get("status")
                    application.importance = app.get("importance")
                    application.archived = app.get("archived")
                    application.assess = app.get("assess")
                    application.assessPending = app.get("assessPending")
                    application.primary = app.get("primary")
                    application.master = app.get("master")
                    application.notes = app.get("notes")
                    application.roles = app.get("roles")
                    application.tags = app.get("tags")
                    application.parentApplicationId = app.get("parentApplicationId")
                    application.techs = app.get("techs")
                    application.policies = app.get("policies")
                    application.missingRequiredFields = app.get("missingRequiredFields")
                    application.protect = app.get("protect")
                    application.links = app.get("links")
                    application.last_seen = app.get("last_seen")
                    application.last_reset = app.get("last_reset")
                    application.size_shorthand = app.get("size_shorthand")
                    application.size = app.get("size")
                    application.code_shorthand = app.get("code_shorthand")
                    application.code = app.get("code")
                    application.override_url = app.get("override_url")
                    application.short_name = app.get("short_name")
                    application.importance_description = app.get("importance_description")
                    application.total_modules = app.get("total_modules")
                    application.first_seen = app.get("first_seen")
                    application.onboarded_time = app.get("onboarded_time")
                    
                    applications.append(application)
                    #{'name': 'TestAppName', 'path': '/', 'language': '.NET', 'created': 1732815900000, 'status': 'offline', 'importance': 2, 'archived': False, 'assess': True, 'assessPending': False, 'primary': False, 'master': False, 'notes': '', 'roles': ['ROLE_EDIT', 'ROLE_RULES_ADMIN', 'ROLE_ADMIN', 'ROLE_ORG_AUDITOR', 'ROLE_VIEW'], 'tags': ['ChileInternalWeb', 'BRK_SSO_CONTRAST_Chile', 'ChileMovilkey', 'ChileCWP'], 'parentApplicationId': '0e9c46a5-c56a-4dc4-81c2-699096ef871e', 'techs': [], 'policies': [], 'missingRequiredFields': None, 'protect': None, 'links': [{'rel': 'self', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'scores', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/scores', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'platform-score', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/scores/platform', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'security-score', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/scores/security', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'trace-breakdown', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/breakdown/trace', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'rule-type-breakdown', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/breakdown/rule', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'rule-category-breakdown', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/breakdown/category', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'rule-severity-breakdown', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/breakdown/severity', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'trace-status-breakdown', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/breakdown/status', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'servers', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/servers', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'restore', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/restore', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'POST'}, {'rel': 'archive', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/archive', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'POST'}, {'rel': 'reset', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/reset', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'POST'}, {'rel': 'delete', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'DELETE'}, {'rel': 'license', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/license', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}, {'rel': 'techs', 'href': '/ng/23456a3a-6f48-4e23-8f85-0101caa2a233/applications/392d16d0-dcdc-1ab3-9302-fc95eee2747b/techs', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}], 'app_id': '392d16d0-dcdc-1ab3-9302-fc95eee2747b', 'last_seen': 1732817160000, 'last_reset': None, 'size_shorthand': '0k', 'size': 0, 'code_shorthand': '0k', 'code': 0, 'override_url': None, 'short_name': None, 'importance_description': 'MEDIUM', 'total_modules': 1, 'first_seen': 1633618779712, 'onboarded_time': 1661974889534}
                    print(f"Application: {application}")
                    
                    routes_response = getRoutes(headers, params, org_id, app_id)
                    if routes_response.status_code == 200:
                        routes_data = routes_response.json()
                        
                        if routes_data.get("routes"):
                            routes = []
                            for route in routes_data["routes"]:
                                #Route: {'app': {'primary': False, 'master': False, 'child': False, 'importance': None, 'app_id': '1447e578-2a3b-4208-a676-7e0675029bf1', 'name': 'example_application_name', 'parent_app_id': None, 'total_modules': 1, 'language': '.NET', 'context_path': None, 'last_seen': 0, 'importance_description': None}, 'signature': 'com.Service.todo.LLama(System.String Nom, System.String Params, System.String Usuage)', 'servers': [{'name': 'SRVRNAME.com.pkg.domain.com', 'hostname': 'SRVRNAME.com.pkg.domain.com', 'serverpath': 'C:\\Windows\\system32\\inetsrv\\w3wp.exe', 'environment': 'PRODUCTION', 'enabled': True, 'server_id': 234563, 'agent_version': '50.0.11.0'}], 'environments': ['PRODUCTION'], 'vulnerabilities': 0, 'exercised': 1694001720000, 'discovered': 1653667320000, 'status': 'EXERCISED', 'route_hash': '-8522716805463318316', 'route_hash_string': '-8522716805463318316', 'servers_total': 1, 'critical_vulnerabilities': 0}
                                for route_data in routes_data["routes"]:
                                    route = Route()
                                    route.app = route_data.get("app")
                                    route.signature = route_data.get("signature")
                                    route.servers = route_data.get("servers")
                                    route.environments = route_data.get("environments")
                                    route.vulnerabilities = route_data.get("vulnerabilities")
                                    route.exercised = route_data.get("exercised")
                                    if route.exercised:
                                        route.exercised = datetime.datetime.fromtimestamp(route.exercised / 1000).strftime('%m/%d/%Y %H:%M')    
                                    route.discovered = route_data.get("discovered")
                                    if route.discovered:
                                        route.discovered = datetime.datetime.fromtimestamp(route.discovered / 1000).strftime('%m/%d/%Y %H:%M')
                                    route.status = route_data.get("status")
                                    route.route_hash = route_data.get("route_hash")
                                    route.route_hash_string = route_data.get("route_hash_string")
                                    route.servers_total = route_data.get("servers_total")
                                    route.critical_vulnerabilities = route_data.get("critical_vulnerabilities")
                                    routes.append(route)
                                    print(f"Route: {route}")

                    vulnerabilities_list = []
                    body = read_json_file("vulnerability_post_body.json")
                    vulns_response = getVulnerabilities(headers, params, org_id, app_id, json.loads(body))

                    if vulns_response.status_code == 200:
                        vulns_data = vulns_response.json()
                        vulnerabilities = vulns_data.get("items")
                        if (vulnerabilities):
                            vulns = []
                            for vuln in vulnerabilities:
                                vulnerability_data = vuln.get("vulnerability")
                                if vulnerability_data:
                                    vulnerability = Vulnerability()
                                    vulnerability.uuid = vulnerability_data.get("uuid")
                                    #vulnerability.title = vulnerability_data.get("title")
                                    vulnerability.ruleName = vulnerability_data.get("ruleName")
                                    vulnerability.visible = vulnerability_data.get("visible")
                                    vulnerability.severity = vulnerability_data.get("severity")
                                    #vulnerability.defaultSeverity = vulnerability_data.get("defaultSeverity")
                                    #vulnerability.tags = vulnerability_data.get("tags")
                                    vulnerability.application = vulnerability_data.get("application")
                                    vulnerability.lastDetected = vulnerability_data.get("lastDetected")
                                    if vulnerability.lastDetected:
                                        vulnerability.lastDetected = datetime.datetime.fromtimestamp(vulnerability.lastDetected / 1000).strftime('%m/%d/%Y %H:%M')
                                    
                                    vulnerability.firstDetected = vulnerability_data.get("firstDetected")
                                    if vulnerability.firstDetected:
                                        vulnerability.firstDetected = datetime.datetime.fromtimestamp(vulnerability.firstDetected / 1000).strftime('%m/%d/%Y %H:%M')
                                    vulnerability.status = vulnerability_data.get("status")
                                    vulnerability.statusKeycode = vulnerability_data.get("statusKeycode")
                                    vulnerability.subStatus = vulnerability_data.get("subStatus")
                                    vulnerability.violations = vulnerability_data.get("violations")
                                    vulnerability.sessionMetadata = vulnerability_data.get("sessionMetadata")
                                    
                                    vulns.append(vulnerability)
                                    print(f"Vulnerability: {vulnerability}")
        else:
            print("No applications found in response.")
            return


if __name__ == "__main__":
    main()