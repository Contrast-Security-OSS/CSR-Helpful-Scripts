"""
Data models and response objects for the Contrast Security API.
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime


class BaseModel:
    """Base model for all API response objects."""
    
    def __init__(self, data: Dict[str, Any]):
        """Initialize model with raw response data."""
        self._data = data
        
    def __getattr__(self, name: str) -> Any:
        """Allow attribute access to response data."""
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")
    
    def __repr__(self) -> str:
        """String representation of the model."""
        class_name = self.__class__.__name__
        if hasattr(self, 'name'):
            return f"{class_name}(name='{self.name}')"
        elif hasattr(self, 'id'):
            return f"{class_name}(id='{self.id}')"
        else:
            return f"{class_name}(data={self._data})"
    
    def to_dict(self) -> Dict[str, Any]:
        """Return the raw data dictionary."""
        return self._data.copy()


class Application(BaseModel):
    """Represents a Contrast application."""
    
    @property
    def id(self) -> Optional[str]:
        """Application ID."""
        return self._data.get('app_id') or self._data.get('id')
    
    @property
    def name(self) -> Optional[str]:
        """Application name."""
        return self._data.get('name')
    
    @property
    def language(self) -> Optional[str]:
        """Programming language."""
        return self._data.get('language')
    
    @property
    def path(self) -> Optional[str]:
        """Application path."""
        return self._data.get('path')
    
    @property
    def importance(self) -> Optional[str]:
        """Application importance level."""
        return self._data.get('importance')
    
    @property
    def tags(self) -> List[str]:
        """Application tags."""
        return self._data.get('tags', [])


class Vulnerability(BaseModel):
    """Represents a Contrast vulnerability/trace."""
    
    @property
    def id(self) -> Optional[str]:
        """Vulnerability ID."""
        return self._data.get('uuid') or self._data.get('id')
    
    @property
    def title(self) -> Optional[str]:
        """Vulnerability title."""
        return self._data.get('title')
    
    @property
    def severity(self) -> Optional[str]:
        """Vulnerability severity."""
        return self._data.get('severity')
    
    @property
    def status(self) -> Optional[str]:
        """Vulnerability status."""
        return self._data.get('status')
    
    @property
    def rule_name(self) -> Optional[str]:
        """Rule name that detected the vulnerability."""
        return self._data.get('rule_name')
    
    @property
    def application_id(self) -> Optional[str]:
        """ID of the application containing this vulnerability."""
        app = self._data.get('application', {})
        return app.get('app_id') or app.get('id')
    
    @property
    def first_time_seen(self) -> Optional[datetime]:
        """First time this vulnerability was seen."""
        timestamp = self._data.get('first_time_seen')
        if timestamp:
            return datetime.fromtimestamp(timestamp / 1000)  # Convert from milliseconds
        return None
    
    @property
    def last_time_seen(self) -> Optional[datetime]:
        """Last time this vulnerability was seen."""
        timestamp = self._data.get('last_time_seen')
        if timestamp:
            return datetime.fromtimestamp(timestamp / 1000)  # Convert from milliseconds
        return None


class Server(BaseModel):
    """Represents a Contrast server."""
    
    @property
    def id(self) -> Optional[str]:
        """Server ID."""
        return self._data.get('server_id') or self._data.get('id')
    
    @property
    def name(self) -> Optional[str]:
        """Server name."""
        return self._data.get('name')
    
    @property
    def hostname(self) -> Optional[str]:
        """Server hostname."""
        return self._data.get('hostname')
    
    @property
    def type(self) -> Optional[str]:
        """Server type."""
        return self._data.get('type')
    
    @property
    def environment(self) -> Optional[str]:
        """Server environment."""
        return self._data.get('environment')


class Library(BaseModel):
    """Represents a Contrast library."""
    
    @property
    def id(self) -> Optional[str]:
        """Library ID."""
        return self._data.get('hash') or self._data.get('id')
    
    @property
    def filename(self) -> Optional[str]:
        """Library filename."""
        return self._data.get('file_name')
    
    @property
    def version(self) -> Optional[str]:
        """Library version."""
        return self._data.get('version')
    
    @property
    def language(self) -> Optional[str]:
        """Programming language."""
        return self._data.get('language')


class Organization(BaseModel):
    """Represents a Contrast organization."""
    
    @property
    def id(self) -> Optional[str]:
        """Organization ID."""
        return self._data.get('organization_uuid') or self._data.get('id')
    
    @property
    def name(self) -> Optional[str]:
        """Organization name."""
        return self._data.get('name')


class PaginatedResponse:
    """Represents a paginated API response."""
    
    def __init__(self, data: Dict[str, Any], model_class: type = BaseModel):
        """
        Initialize paginated response.
        
        Args:
            data: Raw response data
            model_class: Class to wrap individual items with
        """
        self._data = data
        self._model_class = model_class
    
    @property
    def items(self) -> List[BaseModel]:
        """List of items in the response."""
        items_data = self._data.get('items') or self._data.get('traces') or self._data.get('applications') or []
        return [self._model_class(item) for item in items_data]
    
    @property
    def count(self) -> int:
        """Total number of items."""
        return self._data.get('count', 0)
    
    @property
    def total_elements(self) -> int:
        """Total elements available."""
        return self._data.get('totalElements', self.count)
    
    @property
    def page(self) -> int:
        """Current page number."""
        return self._data.get('page', 0)
    
    @property
    def size(self) -> int:
        """Page size."""
        return self._data.get('size', len(self.items))
    
    @property
    def total_pages(self) -> int:
        """Total number of pages."""
        return self._data.get('totalPages', 1)
    
    def __len__(self) -> int:
        """Return number of items in current page."""
        return len(self.items)
    
    def __iter__(self):
        """Allow iteration over items."""
        return iter(self.items)
    
    def __getitem__(self, index: int) -> BaseModel:
        """Allow indexing of items."""
        return self.items[index]