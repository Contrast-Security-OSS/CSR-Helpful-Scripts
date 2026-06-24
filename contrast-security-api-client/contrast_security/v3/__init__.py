"""
V3 API module for Contrast Security API.

This module provides access to the latest V3 API endpoints.
"""

from .applications import ApplicationsAPI
from .vulnerabilities import VulnerabilitiesAPI  
from .servers import ServersAPI
from .libraries import LibrariesAPI
from .organizations import OrganizationsAPI
from .users import UsersAPI
from .reports import ReportsAPI
from .traces import TracesAPI
from .attacks import AttacksAPI
from .coverage import CoverageAPI
from .metadata import MetadataAPI
from .tags import TagsAPI
from .security import SecurityAPI
from .protection_rules import ProtectionRulesAPI


class V3API:
    """V3 API client providing access to all V3 endpoints."""
    
    def __init__(self, client):
        """Initialize V3 API with reference to main client."""
        self.client = client
        
        # Initialize all API endpoint modules
        self.applications = ApplicationsAPI(client)
        self.vulnerabilities = VulnerabilitiesAPI(client)
        self.servers = ServersAPI(client)  
        self.libraries = LibrariesAPI(client)
        self.organizations = OrganizationsAPI(client)
        self.users = UsersAPI(client)
        self.reports = ReportsAPI(client)
        self.traces = TracesAPI(client)
        self.attacks = AttacksAPI(client)
        self.coverage = CoverageAPI(client)
        self.metadata = MetadataAPI(client)
        self.tags = TagsAPI(client)
        self.security = SecurityAPI(client)
        self.protection_rules = ProtectionRulesAPI(client)