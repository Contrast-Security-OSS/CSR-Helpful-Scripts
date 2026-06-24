"""
Traces API endpoints for V3 (alias for vulnerabilities).
"""

from .vulnerabilities import VulnerabilitiesAPI


class TracesAPI(VulnerabilitiesAPI):
    """Traces API client (alias for VulnerabilitiesAPI)."""
    pass