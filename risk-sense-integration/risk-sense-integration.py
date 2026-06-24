#!/usr/bin/env python3
"""
Contrast Security - RiskSense Integration

This script fetches vulnerability data from Contrast Security (both SAST and Assess/IAST)
and exports it to a CSV file in RiskSense format.

Features:
- Fetches SAST (Contrast Scan) vulnerabilities
- Fetches Assess (IAST) vulnerabilities
- Outputs combined data in RiskSense-compatible CSV format
- Reads credentials from ../.creds file with interactive prompts as fallback
"""

import os
import requests
import base64
import getpass
import json
import csv
from datetime import datetime

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================

# Read credentials from .creds file
def read_creds_file(filename="../.creds"):
    """
    Read credentials from a .creds file
    
    Args:
        filename: Path to the credentials file
        
    Returns:
        Dictionary of credentials
    """
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

# Initialize credentials from .creds file
creds = read_creds_file()
contrast_url = creds.get("CONTRAST_URL", "")
org_id = creds.get("ORG_ID", "")
username = creds.get("USERNAME", "")
api_key = creds.get("API_KEY", "")
service_key = creds.get("SERVICE_KEY", "")

# =============================================================================
# API FUNCTIONS
# =============================================================================

def get_applications(headers, org_id):
    """
    Fetch all applications from Contrast
    
    Args:
        headers: HTTP headers including authorization
        org_id: Organization ID
        
    Returns:
        JSON response with applications or None if error
    """
    url = f"{contrast_url}/api/ng/{org_id}/applications"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error fetching applications: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Exception fetching applications: {str(e)}")
        return None


def get_scan_projects(headers, org_id, page=0, size=100):
    """
    Fetch SAST scan projects from Contrast Scan
    
    Args:
        headers: HTTP headers including authorization
        org_id: Organization ID
        page: Page number for pagination
        size: Number of results per page
        
    Returns:
        JSON response with scan projects or None if error
    """
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/overview?page={page}&size={size}&archived=false"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error fetching projects: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Exception fetching projects: {str(e)}")
        return None


def get_scan_results(headers, org_id, project_id, scan_id):
    """
    Fetch SAST scan results in SARIF format
    
    Args:
        headers: HTTP headers including authorization
        org_id: Organization ID
        project_id: Scan project ID
        scan_id: Specific scan ID
        
    Returns:
        SARIF JSON response or None if error
    """
    url = f"{contrast_url}/api/sast/organizations/{org_id}/projects/{project_id}/scans/{scan_id}/sarif"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Warning: Could not fetch scan results for project {project_id}, scan {scan_id}: {response.status_code}")
            return None
    except Exception as e:
        print(f"Exception fetching scan results: {str(e)}")
        return None


def get_assess_vulnerabilities(headers, org_id, vuln_post_data):
    """
    Fetch Assess (IAST) vulnerabilities from Contrast
    
    Args:
        headers: HTTP headers including authorization
        org_id: Organization ID
        vuln_post_data: Filter criteria for vulnerabilities
        
    Returns:
        JSON response with vulnerabilities or None if error
    """
    url = f"{contrast_url}/api/ng/organizations/{org_id}/orgtraces/ui?expand=application&offset=0&limit=1000&sort=-severity"
    params = {"expand": ["application"]}
    
    try:
        response = requests.post(url, headers=headers, params=params, json=vuln_post_data)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Warning: Could not fetch Assess vulnerabilities: {response.status_code}")
            return None
    except Exception as e:
        print(f"Exception fetching Assess vulnerabilities: {str(e)}")
        return None

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def parse_location(location_obj):
    """
    Parse SARIF location object to Ruby-style hash format
    
    Args:
        location_obj: SARIF location object
        
    Returns:
        String in format: {"file"=>"path/to/file", "start_line"=>10}
    """
    if not location_obj:
        return ""

    physical_location = location_obj.get('physicalLocation', {})
    artifact_location = physical_location.get('artifactLocation', {})
    region = physical_location.get('region', {})

    file_path = artifact_location.get('uri', '')
    start_line = region.get('startLine', '')
    end_line = region.get('endLine', '')

    # Build Ruby-style hash format
    parts = []
    if file_path:
        parts.append(f'"file"=>"{file_path}"')
    if start_line:
        parts.append(f'"start_line"=>{start_line}')
    if end_line and end_line != start_line:
        parts.append(f'"end_line"=>{end_line}')

    return '{' + ', '.join(parts) + '}' if parts else ""


def get_severity_score(severity):
    """
    Map severity string to numeric score
    
    Args:
        severity: Severity level (critical, high, medium, low, note)
        
    Returns:
        Numeric score (10, 8, 5, 3, or 1)
    """
    severity_map = {
        'critical': 10,
        'high': 8,
        'medium': 5,
        'low': 3,
        'note': 1
    }
    return severity_map.get(severity.lower() if severity else '', 0)

# =============================================================================
# VULNERABILITY PROCESSING FUNCTIONS
# =============================================================================

def process_assess_vulnerabilities(assess_data, app_name, app_id, group_name="SDIT-RA"):
    """
    Process Assess (IAST) vulnerabilities and convert to CSV format
    
    Args:
        assess_data: Dictionary containing 'items' array of vulnerabilities
        app_name: Application name
        app_id: Application ID
        group_name: Group name for organization (default: SDIT-RA)
        
    Returns:
        List of dictionaries representing CSV rows
        
    CSV Field Mappings from Contrast Assess API:
    ============================================
    CSV Field              <- API Field (vuln object)
    ------------------------------------------------------------
    Group Name             <- group_name parameter (hardcoded)
    Project Name           <- app_name parameter
    Tool                   <- "Contrast" (hardcoded)
    Scanner Name           <- "Contrast Assess" (hardcoded)
    Status                 <- vuln['status'] (mapped to 'detected' if open)
    Vulnerability          <- vuln['ruleName']
    Details                <- vuln['title']
    Additional Info        <- "" (empty)
    Severity               <- vuln['severity']
    CVE                    <- vuln['cve']
    CWE                    <- vuln['references'][].id (where type='CWE')
    Other Identifiers      <- vuln['ruleName']
    Detected At            <- vuln['lastDetected'] (formatted as UTC timestamp)
    Location               <- vuln['evidence'][0] (file_name, line_number)
    Activity               <- "FALSE" (hardcoded)
    Comments               <- "" (empty)
    sast-plugin-id         <- "{group_name}/{app_name}/{uuid[:6]}"
    CVSS Vectors           <- "" (empty)
    Dismissal Reason       <- "" (empty)
    Vulnerability ID       <- vuln['uuid']
    APPID                  <- vuln['application']['id']
    SeverityScore          <- Numeric mapping of severity
    Address                <- app_name parameter
    """
    csv_rows = []

    if not assess_data or 'items' not in assess_data:
        return csv_rows

    for vuln in assess_data.get('items', []):
        # Extract core vulnerability information
        uuid = vuln.get('uuid', '')
        title = vuln.get('title', '')
        rule_name = vuln.get('ruleName', '')
        severity = vuln.get('severity', 'MEDIUM').lower()
        status = vuln.get('status', 'Reported')
        
        # Get application information
        app_info = vuln.get('application', {})
        application_id = app_info.get('id', app_id)
        
        # Get CVE if available
        cve = vuln.get('cve', '')
        
        # Extract CWE from references
        cwe = ""
        references = vuln.get('references', [])
        for ref in references:
            if ref.get('type') == 'CWE':
                cwe = f"CWE-{ref.get('id', '')}"
                break
        
        # Get detection timestamps
        last_detected = vuln.get('lastDetected', '')
        
        # Format detected at timestamp
        detected_at = ""
        if last_detected:
            try:
                dt = datetime.fromtimestamp(last_detected / 1000)
                detected_at = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            except:
                detected_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Extract location from evidence
        location = ""
        evidence = vuln.get('evidence', [])
        if evidence and len(evidence) > 0:
            first_ev = evidence[0]
            file_name = first_ev.get('file_name', '')
            line_number = first_ev.get('line_number', '')
            if file_name:
                parts = [f'"file"=>"{file_name}"']
                if line_number:
                    parts.append(f'"start_line"=>{line_number}')
                location = '{' + ', '.join(parts) + '}'
        
        # Build CSV row - modify field mappings here as needed
        csv_row = {
            'Group Name': group_name,
            'Project Name': app_name,
            'Tool': 'Contrast',
            'Scanner Name': 'Contrast Assess',
            'Status': 'detected' if status in ['Reported', 'Confirmed', 'Suspicious'] else status.lower(),
            'Vulnerability': rule_name,
            'Details': title,
            'Additional Info': '',
            'Severity': severity,
            'CVE': cve,
            'CWE': cwe,
            'Other Identifiers': rule_name,
            'Detected At': detected_at,
            'Location': location,
            'Activity': 'FALSE',
            'Comments': '',
            'sast-plugin-id': f"{group_name.lower()}/{app_name}/{uuid[:6]}",
            'CVSS Vectors': '',
            'Dismissal Reason': '',
            'Vulnerability ID': uuid,
            'APPID': application_id,
            'SeverityScore': get_severity_score(severity),
            'Address': app_name
        }
        
        csv_rows.append(csv_row)
    
    return csv_rows


def process_scan_results(sarif_data, project_name, group_name="SDIT-RA"):
    """
    Process SAST scan results (SARIF format) and convert to CSV format
    
    Args:
        sarif_data: SARIF format scan results
        project_name: Name of the scan project
        group_name: Group name for organization (default: SDIT-RA)
        
    Returns:
        List of dictionaries representing CSV rows
        
    CSV Field Mappings from SARIF Format:
    =====================================
    CSV Field              <- SARIF Field
    ------------------------------------------------------------
    Group Name             <- group_name parameter (hardcoded)
    Project Name           <- project_name parameter
    Tool                   <- "Contrast" (hardcoded)
    Scanner Name           <- run.tool.driver.name
    Status                 <- "detected" (hardcoded)
    Vulnerability          <- result.message.text or rule.name
    Details                <- rule.fullDescription.text
    Additional Info        <- rule.help.text
    Severity               <- result.level (mapped to critical/high/medium/low)
    CVE                    <- "" (not available in SARIF)
    CWE                    <- result.taxa[] (where id starts with 'CWE-')
    Other Identifiers      <- result.ruleId
    Detected At            <- Current UTC timestamp
    Location               <- result.locations[0] (file, start_line, end_line)
    Activity               <- "FALSE" (hardcoded)
    Comments               <- "" (empty)
    sast-plugin-id         <- "{group_name}/{project_name}/{ruleIndex}"
    CVSS Vectors           <- "" (empty)
    Dismissal Reason       <- "" (empty)
    Vulnerability ID       <- result.ruleIndex
    APPID                  <- "" (empty - not available for SAST)
    SeverityScore          <- Numeric mapping of severity
    Address                <- project_name parameter
    """
    csv_rows = []

    if not sarif_data or 'runs' not in sarif_data:
        return csv_rows

    for run in sarif_data.get('runs', []):
        tool = run.get('tool', {})
        driver = tool.get('driver', {})
        scanner_name = driver.get('name', 'Contrast Scan')

        # Build rules lookup for additional details
        rules = {}
        for rule in driver.get('rules', []):
            rule_id = rule.get('id', '')
            rules[rule_id] = rule

        # Process each vulnerability result
        results = run.get('results', [])
        for result in results:
            rule_id = result.get('ruleId', '')
            rule = rules.get(rule_id, {})

            # Extract vulnerability information
            message = result.get('message', {})
            vulnerability_name = message.get('text', rule.get('name', ''))

            # Get full description/details
            full_description = rule.get('fullDescription', {})
            details = full_description.get('text', rule.get('shortDescription', {}).get('text', ''))

            # Get help/additional info
            help_obj = rule.get('help', {})
            additional_info = help_obj.get('text', '')

            # Extract and map severity
            level = result.get('level', 'warning')
            severity_map = {
                'error': 'critical',
                'warning': 'medium',
                'note': 'low',
                'none': 'note'
            }
            severity = severity_map.get(level, 'medium')

            # Check for severity override in properties
            properties = result.get('properties', {})
            if 'severity' in properties:
                severity = properties.get('severity', severity)

            # Extract CWE from taxa
            cwe = ""
            taxa = result.get('taxa', [])
            for taxon in taxa:
                taxon_id = taxon.get('id', '')
                if taxon_id.startswith('CWE-'):
                    cwe = taxon_id
                    break

            # Get location
            locations = result.get('locations', [])
            location = parse_location(locations[0]) if locations else ""

            # Get detected at timestamp
            detected_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

            # Other identifiers
            other_identifiers = rule_id if rule_id else ""

            # Get rule index for unique ID
            rule_index = result.get('ruleIndex', '')

            # Build CSV row - modify field mappings here as needed
            csv_row = {
                'Group Name': group_name,
                'Project Name': project_name,
                'Tool': 'Contrast',
                'Scanner Name': scanner_name,
                'Status': 'detected',
                'Vulnerability': vulnerability_name,
                'Details': details,
                'Additional Info': additional_info,
                'Severity': severity,
                'CVE': '',
                'CWE': cwe,
                'Other Identifiers': other_identifiers,
                'Detected At': detected_at,
                'Location': location,
                'Activity': 'FALSE',
                'Comments': '',
                'sast-plugin-id': f"{group_name.lower()}/{project_name}/{rule_index}",
                'CVSS Vectors': '',
                'Dismissal Reason': '',
                'Vulnerability ID': rule_index,
                'APPID': '',
                'SeverityScore': get_severity_score(severity),
                'Address': project_name
            }

            csv_rows.append(csv_row)

    return csv_rows

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Main execution function"""
    global contrast_url, org_id, username, api_key, service_key

    print("=" * 60)
    print("Contrast Security - RiskSense Integration")
    print("SAST & Assess Vulnerability Export for RiskSense")
    print("=" * 60)

    # Prompt for credentials with defaults from .creds file
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

    # Build authorization headers
    auth_str = f"{username}:{service_key}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()
    
    headers = {
        'Authorization': f"Basic {auth_b64}",
        'API-Key': api_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Collect all vulnerability data
    all_vulnerabilities = []

    # =========================================================================
    # FETCH SAST VULNERABILITIES
    # =========================================================================
    print("\n" + "=" * 60)
    print("Fetching SAST scan projects...")
    projects_data = get_scan_projects(headers, org_id)

    if projects_data:
        projects = projects_data.get('content', [])
        if projects:
            print(f"Found {len(projects)} SAST project(s)")
            
            for project in projects:
                project_id = project.get('id')
                project_name = project.get('name', 'Unknown')
                last_scan_id = project.get('lastScanId')

                print(f"\nProcessing SAST: {project_name}")

                if not last_scan_id:
                    print(f"  No scan results available")
                    continue

                # Get scan results
                sarif_data = get_scan_results(headers, org_id, project_id, last_scan_id)

                if sarif_data:
                    vulnerabilities = process_scan_results(sarif_data, project_name)
                    all_vulnerabilities.extend(vulnerabilities)
                    print(f"  Found {len(vulnerabilities)} SAST vulnerability/vulnerabilities")
                else:
                    print(f"  Could not retrieve scan results")
        else:
            print("No SAST projects found")
    else:
        print("Could not retrieve SAST projects")

    # =========================================================================
    # FETCH ASSESS VULNERABILITIES
    # =========================================================================
    print("\n" + "=" * 60)
    print("Fetching Assess applications...")
    apps_data = get_applications(headers, org_id)

    if apps_data:
        applications = apps_data.get('applications', [])
        if applications:
            print(f"Found {len(applications)} application(s)")
            
            # Collect application IDs
            app_ids = [app.get('app_id') for app in applications if app.get('app_id')]
            
            # Prepare vulnerability filter
            vuln_post_data = {
                "quickFilter": "OPEN",
                "modules": app_ids,
                "servers": [],
                "filterTags": [],
                "severities": [],
                "status": [],
                "substatus": [],
                "vulnTypes": [],
                "environments": [],
                "urls": [],
                "sinks": [],
                "securityStandards": [],
                "appVersionTags": [],
                "routes": [],
                "tracked": False,
                "untracked": False,
                "technologies": [],
                "applicationTags": [],
                "applicationMetadataFilters": [],
                "applicationImportances": [],
                "languages": [],
                "licensedOnly": False,
                "protectStatuses": []
            }
            
            print("\nFetching Assess vulnerabilities...")
            assess_data = get_assess_vulnerabilities(headers, org_id, vuln_post_data)
            
            if assess_data:
                items = assess_data.get('items', [])
                print(f"Found {len(items)} Assess vulnerabilities across all applications")
                
                # Group vulnerabilities by application
                # Note: API returns nested structure: items[].vulnerability
                vulns_by_app = {}
                for item in items:
                    vuln = item.get('vulnerability', {})
                    app = vuln.get('application', {})
                    app_id = app.get('id', '')
                    app_name = app.get('name', 'Unknown')
                    
                    if app_id not in vulns_by_app:
                        vulns_by_app[app_id] = {'name': app_name, 'items': []}
                    vulns_by_app[app_id]['items'].append(vuln)
                
                # Process each application's vulnerabilities
                for app_id, app_data in vulns_by_app.items():
                    app_name = app_data['name']
                    app_items = app_data['items']
                    print(f"\nProcessing Assess: {app_name}")
                    print(f"  Found {len(app_items)} Assess vulnerability/vulnerabilities")
                    
                    temp_assess_data = {'items': app_items}
                    vulnerabilities = process_assess_vulnerabilities(temp_assess_data, app_name, app_id)
                    all_vulnerabilities.extend(vulnerabilities)
            else:
                print("Could not retrieve Assess vulnerabilities")
        else:
            print("No applications found")
    else:
        print("Could not retrieve applications")

    # =========================================================================
    # WRITE CSV OUTPUT
    # =========================================================================
    if all_vulnerabilities:
        output_file = os.path.join(os.path.dirname(__file__), 'RiskSenseIntegration_vulnerabilities.csv')

        # Define CSV column headers - modify this list to change output columns
        fieldnames = [
            'Group Name', 'Project Name', 'Tool', 'Scanner Name', 'Status',
            'Vulnerability', 'Details', 'Additional Info', 'Severity', 'CVE', 'CWE',
            'Other Identifiers', 'Detected At', 'Location', 'Activity', 'Comments',
            'sast-plugin-id', 'CVSS Vectors', 'Dismissal Reason', 'Vulnerability ID',
            'APPID', 'SeverityScore', 'Address'
        ]

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_vulnerabilities)

        print(f"\n{'=' * 60}")
        print(f"✓ CSV file created: {output_file}")
        print(f"Total vulnerabilities exported: {len(all_vulnerabilities)}")
        print(f"{'=' * 60}")
    else:
        print("\n✗ No vulnerabilities found to export")


if __name__ == "__main__":
    main()
