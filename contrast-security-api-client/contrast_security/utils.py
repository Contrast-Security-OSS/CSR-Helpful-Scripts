# SPDX-License-Identifier: Apache-2.0
"""
Utility functions and helpers for the Contrast Security API client.
"""

import copy
import json
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse


# Cells beginning with any of these are interpreted as formulas by Excel,
# Numbers, LibreOffice Calc, and Google Sheets.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Keys whose values may contain captured request/response material from
# production traffic (cookies, auth headers, correlation IDs).
_REDACT_KEYS = frozenset({
    "authorization",
    "api-key",
    "x-api-key",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "x-forwarded-for",
    "sessionmetadata",
    "session_metadata",
    "request_headers",
    "response_headers",
    "headers",
})


def safe_csv_cell(value: Any) -> str:
    """
    Make a value safe to write into a CSV cell, preventing CSV-injection.

    Returns the string form of `value`. If the result starts with a character
    that spreadsheet software treats as a formula prefix, a single leading
    quote is added so the cell renders as literal text.

    Args:
        value: Any value destined for a csv.writer row.

    Returns:
        A string safe to pass to csv.writer.writerow.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if text and text[0] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


def redact_response(data: Any, _depth: int = 0) -> Any:
    """
    Return a deep copy of `data` with sensitive fields replaced by "<redacted>".

    Walks nested dicts and lists. Targets header names (Authorization, API-Key,
    cookies) and Contrast-specific fields known to carry captured production
    traffic (sessionMetadata, request_headers, response_headers).

    Useful before passing API responses to print() or logging in a context where
    the output may end up in CI logs, shared terminals, or screen recordings.

    Args:
        data: Anything JSON-serializable.

    Returns:
        A redacted copy. The input is not mutated.
    """
    if _depth > 50:
        return "<truncated:max-depth>"
    if isinstance(data, dict):
        out = {}
        for key, value in data.items():
            if isinstance(key, str) and key.lower() in _REDACT_KEYS:
                out[key] = "<redacted>"
            else:
                out[key] = redact_response(value, _depth + 1)
        return out
    if isinstance(data, list):
        return [redact_response(item, _depth + 1) for item in data]
    return data


def build_url(base_url: str, *path_parts: str, **params: Any) -> str:
    """
    Build a complete URL from base URL and path parts.
    
    Args:
        base_url: Base URL (e.g., 'https://app.contrastsecurity.com')
        *path_parts: URL path segments
        **params: Query parameters
        
    Returns:
        Complete URL string
    """
    # Ensure base_url ends with /
    if not base_url.endswith('/'):
        base_url += '/'
    
    # Join all path parts
    path = '/'.join(str(part).strip('/') for part in path_parts if part)
    
    # Combine base URL and path
    url = urljoin(base_url, path)
    
    # Add query parameters if provided
    if params:
        query_parts = []
        for key, value in params.items():
            if value is not None:
                if isinstance(value, bool):
                    value = str(value).lower()
                elif isinstance(value, (list, tuple)):
                    # Handle array parameters
                    for item in value:
                        query_parts.append(f"{key}={item}")
                    continue
                query_parts.append(f"{key}={value}")
        
        if query_parts:
            url += ('&' if '?' in url else '?') + '&'.join(query_parts)
    
    return url


def format_date(date_value: Optional[Union[str, int]]) -> Optional[str]:
    """
    Format date value for API requests.
    
    Args:
        date_value: Date as string, timestamp, or None
        
    Returns:
        Formatted date string or None
    """
    if not date_value:
        return None
        
    if isinstance(date_value, int):
        # Assume timestamp in milliseconds
        return str(date_value)
    
    return str(date_value)


def validate_uuid(uuid_string: str) -> bool:
    """
    Validate UUID format.
    
    Args:
        uuid_string: UUID string to validate
        
    Returns:
        True if valid UUID format
    """
    import re
    
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_pattern.match(uuid_string))


def chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split a list into chunks of specified size.
    
    Args:
        items: List to chunk
        chunk_size: Maximum size of each chunk
        
    Returns:
        List of chunked sublists
    """
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def safe_json_loads(json_str: str) -> Optional[Dict[str, Any]]:
    """
    Safely parse JSON string.
    
    Args:
        json_str: JSON string to parse
        
    Returns:
        Parsed JSON dict or None if invalid
    """
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return None


def extract_org_id_from_url(url: str) -> Optional[str]:
    """
    Extract organization ID from Contrast URL.
    
    Args:
        url: Contrast URL containing organization ID
        
    Returns:
        Organization ID or None if not found
    """
    # Pattern to match org UUIDs in URLs like /api/ng/{orgId}/...
    import re
    
    pattern = r'/api/(?:ng/)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    match = re.search(pattern, url, re.IGNORECASE)
    
    return match.group(1) if match else None


def retry_with_backoff(
    func: callable,
    max_retries: int = 3,
    backoff_factor: float = 0.3,
    status_codes_to_retry: Optional[List[int]] = None,
) -> Any:
    """
    Retry function with exponential backoff.
    
    Args:
        func: Function to retry
        max_retries: Maximum number of retries
        backoff_factor: Multiplier for backoff delay
        status_codes_to_retry: HTTP status codes that should trigger retry
        
    Returns:
        Function result
        
    Raises:
        Last exception if all retries fail
    """
    if status_codes_to_retry is None:
        status_codes_to_retry = [429, 500, 502, 503, 504]
    
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            return func()
        except Exception as e:
            last_exception = e
            
            # Check if we should retry based on status code
            if hasattr(e, 'status_code') and e.status_code not in status_codes_to_retry:
                raise e
            
            if attempt == max_retries:
                raise e
            
            # Calculate backoff delay
            delay = backoff_factor * (2 ** attempt)
            time.sleep(delay)
    
    raise last_exception


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file system operations.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import re
    
    # Remove or replace unsafe characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing whitespace and dots
    filename = filename.strip(' .')
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_len = 255 - len(ext) - 1 if ext else 255
        filename = name[:max_name_len] + ('.' + ext if ext else '')
    
    return filename or 'unnamed'


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary (takes precedence)
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result