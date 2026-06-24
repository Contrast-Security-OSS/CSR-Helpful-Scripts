# Contrast Security API Client Examples

This directory contains practical examples demonstrating how to use the Contrast Security API client library.

## Examples Overview

### 1. [basic_usage.py](basic_usage.py)
Demonstrates the fundamental usage patterns:
- Client initialization with credentials
- Getting organizations, applications, vulnerabilities, and servers
- Basic error handling
- Response data access

**Key Features:**
- Shows both direct credential and credentials file initialization
- Displays summary information for all major entity types
- Demonstrates pagination handling

### 2. [vulnerability_management.py](vulnerability_management.py)
Advanced vulnerability management operations:
- Filtering vulnerabilities by severity and status
- Grouping vulnerabilities by type and application
- Updating vulnerability status and comments
- Working with vulnerability tags and metadata

**Key Features:**
- Complex filtering and searching
- Vulnerability status management
- Bulk operations across applications
- Tag and metadata handling

### 3. [application_management.py](application_management.py)
Application and library management:
- Getting detailed application information
- Managing application libraries and dependencies
- Adding and managing application tags/metadata
- Library vulnerability analysis

**Key Features:**
- Expanded data retrieval (scores, technologies, libraries)
- Metadata and tag management
- Library security assessment
- Cross-application analysis

### 4. [credentials_usage.py](credentials_usage.py)
Comprehensive credential management:
- Creating and validating credentials files
- Multiple credential file location strategies
- Environment-based configuration
- Credential file format validation

**Key Features:**
- Credentials file creation and validation
- Multiple file location handling
- Environment variable integration
- Configuration best practices

### 5. **NEW: [fetch_creds_interactive.py](fetch_creds_interactive.py)**
Interactive credential collection using the CSR-Helpful-Scripts system:
- Uses the existing `fetch_creds.py` system from the parent repository
- Reads from `.creds` file with interactive prompting for missing values
- Integrates seamlessly with existing CSR workflow

**Key Features:**
- Interactive credential prompting
- Automatic `.creds` file reading
- Seamless integration with CSR-Helpful-Scripts
- Real credential validation

### 6. **NEW: [fetch_creds_noninteractive.py](fetch_creds_noninteractive.py)**
Non-interactive credential loading:
- Only uses `.creds` file, no prompting
- Perfect for automation and CI/CD
- Comprehensive error handling and troubleshooting

**Key Features:**
- Non-interactive mode for automation
- Detailed error diagnostics
- Production-ready authentication
- Comprehensive API testing

### 7. **NEW: [comprehensive_auth_demo.py](comprehensive_auth_demo.py)**
Complete authentication methods demonstration:
- Shows all available authentication approaches
- Compares interactive vs non-interactive modes
- Includes API testing and validation
- Production vs development workflows

**Key Features:**
- All authentication methods in one place
- Method comparison and recommendations
- Comprehensive API testing
- Setup troubleshooting guidance

## Getting Started

### Recommended Approach: Use fetch_creds.py System

The **easiest and most integrated** way to use this API client is with the existing CSR-Helpful-Scripts credential system:

1. **Set up .creds file** (one-time setup):
   ```bash
   # From the project root directory
   cp template.creds .creds
   nano .creds  # Edit with your actual Contrast Security credentials
   ```

2. **Use the API client with automatic credential loading**:
   ```python
   from contrast_security import ContrastAPI
   
   # Interactive mode (prompts for missing credentials)
   client = ContrastAPI.from_fetch_creds()
   
   # Non-interactive mode (only uses .creds file - good for automation)
   client = ContrastAPI.from_fetch_creds(interactive=False)
   ```

3. **Run an example**:
   ```bash
   cd contrast-security-api-client/examples
   python3 fetch_creds_noninteractive.py
   ```

### Alternative Approaches

If you prefer not to use the fetch_creds system, you can still use traditional methods:

### Alternative Approaches

If you prefer not to use the fetch_creds system, you can still use traditional methods:

**Method 1: Direct credentials**
```python
client = ContrastAPI(
    base_url="https://app.contrastsecurity.com",
    api_key="your-api-key-here",
    service_key="your-service-key-here",
    organization_id="your-org-id-here"
)
```

**Method 2: Credentials file**
```python
# Create contrast_credentials.txt with:
# api_key=your-api-key-here
# service_key=your-service-key-here
# organization_id=your-org-id-here

client = ContrastAPI(
    base_url="https://app.contrastsecurity.com",
    credentials_file="contrast_credentials.txt"
)
```

## Credential Setup

### Using .creds File (Recommended)

The API client integrates with the existing CSR-Helpful-Scripts credential system:

1. **Copy the template**:
   ```bash
   cp ../template.creds ../.creds
   ```

2. **Edit with your credentials**:
   ```bash
   nano ../.creds
   ```

3. **Required fields**:
   ```ini
   CONTRAST_URL=https://your-instance.contrastsecurity.com
   ORG_ID=your-organization-uuid
   USERNAME=your-username
   API_KEY=your-api-key
   SERVICE_KEY=your-service-key
   ```

### Getting Your Credentials

1. **Log in to Contrast Security**: Access your Contrast Security platform
2. **Navigate to User Settings**: Click on your profile → User Settings
3. **API Keys Section**: Find the "API" section
4. **Copy Credentials**: 
   - API Key: Your personal API key
   - Service Key: Your organization's service key
   - Organization ID: Your organization UUID

### Credentials File Format

Create a file named `contrast_credentials.txt`:

```ini
# Contrast Security Credentials
api_key=your-actual-api-key-here
service_key=your-actual-service-key-here
organization_id=your-actual-org-id-here

# Optional: Custom base URL
# base_url=https://app.contrastsecurity.com
```

### Security Best Practices

- **Never commit credentials** to version control
- **Use environment variables** for CI/CD pipelines
- **Set appropriate file permissions** (600) on credentials files
- **Rotate credentials regularly** as per your organization's policy
- **Use different credentials** for different environments

## Common Use Cases

### Security Dashboards
Use the examples to build custom security dashboards:
- Application security scores
- Vulnerability trends by severity
- Library vulnerability tracking
- Compliance reporting

### Automated Remediation
Integrate with CI/CD pipelines:
- Automatic vulnerability status updates
- Tag-based policy enforcement
- Notification systems
- Risk assessment automation

### Bulk Operations
Perform operations across multiple applications:
- Bulk tag updates
- Policy application
- Metadata management
- Configuration standardization

## API Coverage

These examples demonstrate usage of:

### V3 API (Latest)
- Applications management
- Vulnerability tracking and management
- Library security assessment
- Server monitoring
- Organization management
- User management
- Metadata and tagging
- Security policies
- Attack monitoring
- Code coverage analysis

### V2 API (Compatibility)
- Legacy application endpoints
- Historical vulnerability data
- Older reporting formats

### V1 API (Legacy)
- Basic application information
- Simple vulnerability listing

## Error Handling

All examples include comprehensive error handling:

```python
from contrast_security.exceptions import ContrastAPIError

try:
    response = client.applications.list()
except ContrastAPIError as e:
    print(f"API Error: {e}")
    print(f"Status Code: {e.status_code}")
    print(f"Response: {e.response_data}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Response Handling

Responses can be handled in multiple ways:

```python
# Raw response
response = client.applications.list()
print(f"Status: {response.status_code}")
raw_data = response.json()

# Using data models (if available)
from contrast_security.models import Application

# Convert to model instances
apps = [Application(app_data) for app_data in raw_data.get('applications', [])]
for app in apps:
    print(f"App: {app.name} ({app.language})")
```

## Need Help?

- **API Documentation**: [Contrast Security API Docs](https://api.contrastsecurity.com/)
- **Package Issues**: Check the main README.md
- **Example Issues**: Create an issue in the repository

## Contributing Examples

To contribute new examples:

1. Follow the existing naming pattern
2. Include comprehensive error handling
3. Add documentation and comments
4. Update this README with the new example
5. Test with various scenarios