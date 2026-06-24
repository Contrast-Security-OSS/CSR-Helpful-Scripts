# SPDX-License-Identifier: Apache-2.0
import argparse
import requests
import base64
import datetime
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

try:
    from contrast_security.utils import redact_response
except ImportError:
    # Fall back to a no-op redactor if the SDK is not installed; warn the operator.
    print("Warning: contrast_security.utils.redact_response not available; output will not be redacted.")
    def redact_response(data, _depth=0):
        return data


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


_session = _make_session()

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

params = {
    "expand": ["apps", "vulns"]
}

def getApplications(headers, params, org_id, contrast_url, offset=0, limit=50):
    """Fetch one page of /applications. Caller paginates."""
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    page_params = dict(params) if params else {}
    page_params["offset"] = offset
    page_params["limit"] = limit
    response = _session.get(url, headers=headers, params=page_params, timeout=(10, 60))
    return response

def getVulnerabilities(headers, params, org_id, app_id, vuln_post_data, contrast_url):
    url = f"{contrast_url}/api/ng/organizations/{org_id}/orgtraces/ui?expand=application&offset=0&limit=25&sort=-severity"
    print(f"URL: {url}")
    response = _session.post(url, headers=headers, params=params, json=vuln_post_data, timeout=(10, 60))
    return response

def getVulnerabilityDetails(headers, params, org_id, vuln_id, contrast_url):
    url = f"{contrast_url}/api/ng/{org_id}/orgtraces/filter/{vuln_id}?expand=events,notes_count,application,server_environments,violations,{vuln_id},skip_links"
    print(f"URL: {url}")
    response = _session.get(url, headers=headers, params=params, timeout=(10, 60))
    return response

def getRoutes(headers, params, org_id, app_id):
    url = f"{contrast_url}/api/ng/{org_id}/applications/{app_id}/route"
    response = _session.get(url, headers=headers, params=params, timeout=(10, 60))
    return response

def getServers(headers, params, org_id):
    url = f"{contrast_url}/api/ng/{org_id}/servers"
    response = _session.get(url, headers=headers, params=params, timeout=(10, 60))
    return response

def putToggleServerProtect(headers, params, org_id, server_id):
    url = f"{contrast_url}/api/ng/{org_id}/servers/{server_id}/defend"
    response = _session.put(url, headers=headers, params=params, timeout=(10, 60))
    return response

def read_json_file(filename):
    with open(filename, "r") as f:
        return f.read()

def main():
    parser = argparse.ArgumentParser(description="Fetch vulnerabilities by business unit (application tags).")
    parser.add_argument("--debug", action="store_true", help="Print full response bodies on HTTP errors.")
    parser.add_argument("--debug-dir", default=None, help="If set, write raw API responses to this directory (chmod 600). Off by default.")
    parser.add_argument("--verbose", action="store_true", help="Print full per-vulnerability details (still redacted).")
    args = parser.parse_args()

    # Get credentials using the shared module
    creds = get_credentials()
    contrast_url = creds["contrast_url"]
    org_id = creds["org_id"]
    headers = creds["headers"]

    def _write_debug(name, payload):
        if not args.debug_dir:
            return
        os.makedirs(args.debug_dir, exist_ok=True)
        path = os.path.join(args.debug_dir, name)
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    # Paginate /applications. Loop until a short page is returned.
    page_size = 50
    offset = 0
    app_list = []
    while True:
        response = getApplications(headers, params, org_id, contrast_url, offset=offset, limit=page_size)
        if response.status_code != 200:
            print(f"Request failed: HTTP {response.status_code}")
            if args.debug:
                print(response.text)
            sys.exit(1)
        data = response.json()
        _write_debug(f"applications_offset_{offset}.json", data)
        page = data.get("applications") or []
        app_list.extend(page)
        if len(page) < page_size:
            break
        offset += page_size

    if app_list:

##### TODO, anything that is absolutely not needed, remove field so it doesn't hold in session memory.
        applications = []
        # Adjust the following path as needed based on actual API response structure
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
                    # Example payload, identifiers are synthetic.
                    #{'name': 'ExampleApp', 'path': '/', 'language': '.NET', 'created': 1732815900000, 'status': 'offline', 'importance': 2, 'archived': False, 'assess': True, 'assessPending': False, 'primary': False, 'master': False, 'notes': '', 'roles': ['ROLE_EDIT', 'ROLE_RULES_ADMIN', 'ROLE_ADMIN', 'ROLE_ORG_AUDITOR', 'ROLE_VIEW'], 'tags': ['ExampleTagA', 'ExampleTagB', 'ExampleTagC', 'ExampleTagD'], 'parentApplicationId': '00000000-0000-0000-0000-000000000000', 'techs': [], 'policies': [], 'missingRequiredFields': None, 'protect': None, 'links': [{'rel': 'self', 'href': '/ng/00000000-0000-0000-0000-000000000000/applications/00000000-0000-0000-0000-000000000001', 'hreflang': None, 'media': None, 'title': None, 'type': None, 'deprecation': None, 'method': 'GET'}], 'app_id': '00000000-0000-0000-0000-000000000001', 'last_seen': 1732817160000, 'last_reset': None, 'size_shorthand': '0k', 'size': 0, 'code_shorthand': '0k', 'code': 0, 'override_url': None, 'short_name': None, 'importance_description': 'MEDIUM', 'total_modules': 1, 'first_seen': 1633618779712, 'onboarded_time': 1661974889534}
                    #print(f"\n\nApplication: {application}")
                    
                    vulnerabilities_list = []
                    body = read_json_file("vulnerability_post_body.json")
                    parsed_body = json.loads(body)
                    parsed_body["modules"] = [app_id]                    
                    vulns_response = getVulnerabilities(headers, params, org_id, app_id, parsed_body, contrast_url)

                    if vulns_response.status_code == 200:
                        vulns_data = vulns_response.json()
                        _write_debug(f"vuln_{app_id}.json", vulns_data)
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
                                    if args.verbose:
                                        print(f"Vulnerability: {redact_response(vulnerability_data)}")

                                    details_response = getVulnerabilityDetails(headers, params, org_id, vulnerability.uuid, contrast_url)
                                    if details_response.status_code == 200:
                                        details_data = details_response.json()
                                        if args.verbose:
                                            print("================================")
                                            print(f"     Vulnerability details: {redact_response(details_data)}")
    else:
        print("No applications found in response.")
        return


if __name__ == "__main__":
    main()