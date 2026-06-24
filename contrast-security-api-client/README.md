# Contrast Security API Client

A comprehensive Python client library for the Contrast Security API, supporting all major API versions (v1, v2, v3).

## Overview

This library provides a complete interface to interact with the Contrast Security TeamServer API, including support for:

- **Applications** - Manage application security testing
- **Vulnerabilities** - Track and manage security vulnerabilities  
- **Servers** - Manage server configurations and protection
- **Libraries** - Software component analysis and management
- **Users & Organizations** - Access control and administration
- **Reporting** - Generate security reports and analytics
- **Protection Rules** - Runtime application self-protection (RASP)

## Features

- 🚀 **Complete API Coverage** - All v1, v2, and v3 endpoints
- 🔐 **Secure Authentication** - API key and service key support
- 📊 **Pagination Support** - Handle large result sets efficiently
- 🔍 **Advanced Filtering** - Rich filtering and search capabilities
- 📈 **Data Expansion** - Retrieve related data in single requests
- ⚡ **Async Support** - Asynchronous operations for better performance
- 🛠️ **Type Hints** - Full typing support for better IDE experience
- 📝 **Comprehensive Docs** - Detailed documentation and examples

## API Version Support

### V3 API (Latest)
- Applications and Application Management
- Vulnerabilities and Trace Management
- Server Management and Protection
- Libraries and Software Component Analysis
- User and Organization Management
- Reporting and Analytics
- Protection Rules and Security Controls
- Attack Monitoring (RASP)

### V2 API
- Core application and vulnerability endpoints
- Server and library management
- Basic reporting functionality

### V1 API (Legacy)
- Basic application and vulnerability operations
- Legacy server management

## Installation

```bash
pip install contrast-security-api-client
```

## Quick Start

```python
from contrast_security import ContrastAPI

# Initialize the client
client = ContrastAPI(
    base_url="https://app.contrastsecurity.com",
    api_key="your-api-key",
    service_key="your-service-key",
    organization_id="your-org-id"
)

# Get all applications
applications = client.applications.list()

# Get vulnerabilities for an application
vulnerabilities = client.vulnerabilities.list_by_application("app-id")

# Get server information
servers = client.servers.list()
```

## Documentation

- [API Reference](docs/api_reference.md)
- [Examples](examples/)
- [Contributing](CONTRIBUTING.md)

## Project Structure

```
contrast-security-api-client/
├── contrast_security/           # Main package
│   ├── __init__.py
│   ├── client.py               # Main API client
│   ├── auth.py                 # Authentication handling
│   ├── exceptions.py           # Custom exceptions
│   ├── utils.py               # Utility functions
│   ├── models/                # Data models and response objects
│   ├── v3/                    # V3 API endpoints
│   ├── v2/                    # V2 API endpoints
│   └── v1/                    # V1 API endpoints (legacy)
├── examples/                  # Usage examples
├── tests/                     # Test suite
├── docs/                      # Documentation
└── scripts/                   # Development scripts
```

## License

MIT License - see [LICENSE](LICENSE) file for details.