# Contributing to Contrast Security API Client

Thank you for your interest in contributing to the Contrast Security API Client! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, conda, etc.)

### Development Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/your-username/contrast-security-api-client.git
   cd contrast-security-api-client
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**:
   ```bash
   pip install -e ".[dev,test]"
   ```

4. **Set up pre-commit hooks** (optional but recommended):
   ```bash
   pre-commit install
   ```

5. **Run tests to verify setup**:
   ```bash
   pytest
   ```

## Project Structure

```
contrast-security-api-client/
├── contrast_security/           # Main package
│   ├── __init__.py             # Package entry point
│   ├── client.py               # Main API client
│   ├── auth.py                 # Authentication handling
│   ├── exceptions.py           # Custom exceptions
│   ├── utils.py                # Utility functions
│   ├── models/                 # Data models
│   │   └── __init__.py
│   ├── v1/                     # V1 API endpoints (legacy)
│   │   └── __init__.py
│   ├── v2/                     # V2 API endpoints
│   │   └── __init__.py
│   └── v3/                     # V3 API endpoints (current)
│       ├── __init__.py
│       ├── applications.py
│       ├── vulnerabilities.py
│       ├── servers.py
│       ├── libraries.py
│       ├── organizations.py
│       ├── users.py
│       ├── reports.py
│       ├── traces.py
│       ├── attacks.py
│       ├── coverage.py
│       ├── metadata.py
│       ├── tags.py
│       ├── security.py
│       └── protection_rules.py
├── examples/                   # Usage examples
├── tests/                      # Test suite
├── docs/                       # Documentation
├── pyproject.toml             # Project configuration
├── README.md                  # Main documentation
└── CONTRIBUTING.md            # This file
```

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line Length**: 88 characters (Black default)
- **String Quotes**: Double quotes for strings, single quotes for dict keys when appropriate
- **Import Organization**: stdlib, third-party, local imports (separated by blank lines)

### Code Formatting

We use [Black](https://black.readthedocs.io/) for code formatting:

```bash
# Format all code
black contrast_security/ tests/ examples/

# Check formatting
black --check contrast_security/ tests/ examples/
```

### Linting

We use [flake8](https://flake8.pycqa.org/) for linting:

```bash
# Run linter
flake8 contrast_security/ tests/ examples/
```

### Type Hints

- Use type hints for all public functions and methods
- Use `typing` module for complex types
- Consider using `Optional` for nullable parameters

Example:
```python
from typing import Dict, List, Optional, Union
import requests

def get_applications(
    self, 
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    expand: Optional[List[str]] = None
) -> requests.Response:
    """Get list of applications."""
    # Implementation
```

### Documentation Strings

Use Google-style docstrings:

```python
def list_vulnerabilities(
    self, 
    severity: Optional[List[str]] = None,
    status: Optional[List[str]] = None
) -> requests.Response:
    """List vulnerabilities with optional filtering.
    
    Args:
        severity: Filter by vulnerability severity levels.
            Valid values: Critical, High, Medium, Low, Note
        status: Filter by vulnerability status.
            Valid values: Reported, Suspicious, Confirmed, etc.
    
    Returns:
        Response object containing vulnerability data.
        
    Raises:
        ContrastAPIError: If the API request fails.
        
    Example:
        >>> client = ContrastAPI(...)
        >>> response = client.vulnerabilities.list(
        ...     severity=["High", "Critical"],
        ...     status=["Reported"]
        ... )
        >>> vulns = response.json()
    """
```

## Testing

### Test Structure

```
tests/
├── conftest.py                # Pytest configuration and fixtures
├── test_client.py            # Main client tests
├── test_auth.py              # Authentication tests
├── test_exceptions.py        # Exception handling tests
├── unit/                     # Unit tests
│   ├── test_v3_applications.py
│   ├── test_v3_vulnerabilities.py
│   └── ...
├── integration/              # Integration tests
│   ├── test_api_integration.py
│   └── ...
└── fixtures/                 # Test data files
    ├── sample_responses/
    └── ...
```

### Writing Tests

1. **Unit Tests**: Test individual functions/methods in isolation
2. **Integration Tests**: Test API interactions (require credentials)
3. **Mock Tests**: Use `responses` library to mock HTTP calls

Example unit test:
```python
import pytest
from unittest.mock import Mock, patch
from contrast_security import ContrastAPI

def test_applications_list_basic(mock_client):
    """Test basic applications listing."""
    # Mock response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "applications": [
            {"app_id": "123", "name": "Test App", "language": "Python"}
        ],
        "count": 1
    }
    
    with patch.object(mock_client, '_make_request', return_value=mock_response):
        response = mock_client.applications.list()
        
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert len(data["applications"]) == 1
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=contrast_security --cov-report=html

# Run specific test file
pytest tests/test_client.py

# Run specific test function
pytest tests/test_client.py::test_client_initialization

# Run integration tests (requires credentials)
pytest tests/integration/ --credentials-file=test_credentials.txt
```

### Test Configuration

Create a `test_credentials.txt` file for integration tests:
```ini
api_key=your-test-api-key
service_key=your-test-service-key
organization_id=your-test-org-id
base_url=https://app.contrastsecurity.com
```

## Documentation

### API Documentation

- Document all public methods with comprehensive docstrings
- Include parameter descriptions, return values, and examples
- Document exceptions that may be raised

### Examples

When adding new functionality:

1. **Create usage examples** in the `examples/` directory
2. **Update example README** to include the new example
3. **Test examples** to ensure they work correctly

### README Updates

Update the main README.md when:
- Adding new major features
- Changing installation requirements
- Modifying the public API
- Adding new examples

## Pull Request Process

### Before Submitting

1. **Run the full test suite** and ensure all tests pass
2. **Update documentation** for any API changes
3. **Add tests** for new functionality
4. **Update CHANGELOG.md** with your changes
5. **Ensure code follows** the style guidelines

### PR Title and Description

- **Use descriptive titles**: "Add support for vulnerability tagging" instead of "Bug fix"
- **Include context**: Explain what problem you're solving
- **Reference issues**: Link to related issues with "Fixes #123"
- **List changes**: Summarize what was added/changed/removed

### PR Template

```markdown
## Description
Brief description of changes and motivation.

## Changes Made
- [ ] Added new feature X
- [ ] Fixed bug Y
- [ ] Updated documentation
- [ ] Added tests

## Testing
- [ ] All existing tests pass
- [ ] Added tests for new functionality
- [ ] Manual testing completed

## Documentation
- [ ] Updated docstrings
- [ ] Updated README if needed
- [ ] Added examples if applicable

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Changelog updated
```

### Review Process

1. **Automated checks** must pass (tests, linting, formatting)
2. **Code review** by maintainer(s)
3. **Address feedback** and update PR as needed
4. **Approval and merge** by maintainer

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **Major (X.0.0)**: Breaking changes
- **Minor (0.X.0)**: New features, backwards compatible
- **Patch (0.0.X)**: Bug fixes, backwards compatible

### Changelog

Update `CHANGELOG.md` with:
- **Date** of release
- **Version number**
- **Changes** categorized as:
  - Added (new features)
  - Changed (changes to existing functionality)
  - Deprecated (features marked for removal)
  - Removed (features removed)
  - Fixed (bug fixes)
  - Security (security-related changes)

### Release Steps

1. **Update version** in `pyproject.toml`
2. **Update CHANGELOG.md** with release notes
3. **Create release PR** and get approval
4. **Tag release** after merging: `git tag v1.2.3`
5. **Push tags**: `git push origin --tags`
6. **Create GitHub release** with changelog content
7. **Build and upload** to PyPI (automated via CI/CD)

## Getting Help

### Questions and Support

- **General questions**: Create a GitHub Discussion
- **Bug reports**: Create a GitHub Issue
- **Feature requests**: Create a GitHub Issue with enhancement label
- **Security issues**: Email security@contrast.security (do not create public issues)

### Communication

- **Be respectful** and professional in all interactions
- **Search existing issues** before creating new ones
- **Provide clear examples** and error messages when reporting bugs
- **Be patient** - maintainers are volunteers with other responsibilities

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/). By participating, you agree to uphold this code.

### Quick Summary

- **Be welcoming** to newcomers
- **Be respectful** of different viewpoints and experiences
- **Accept constructive criticism** gracefully
- **Focus on community benefit** over personal gain
- **Show empathy** towards community members

Thank you for contributing to the Contrast Security API Client! 🙏