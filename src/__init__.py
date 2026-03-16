#!/usr/bin/env python3
"""
Utility functions for the AI-Enhanced Security Scanner
"""

import re
import hashlib
import datetime
import json
from typing import Dict, Any, List, Optional
import urllib.parse

def normalize_url(url: str) -> str:
    """
    Normalize URL by removing fragments and normalizing scheme
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    parsed = urllib.parse.urlparse(url)
    
    # Remove fragment
    parsed = parsed._replace(fragment='')
    
    # Normalize scheme to lowercase
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    # Remove default ports
    if (scheme == 'http' and parsed.port == 80) or \
       (scheme == 'https' and parsed.port == 443):
        netloc = netloc.split(':')[0]
    
    parsed = parsed._replace(scheme=scheme, netloc=netloc)
    
    return urllib.parse.urlunparse(parsed)

def is_same_domain(url1: str, url2: str) -> bool:
    """
    Check if two URLs belong to the same domain
    
    Args:
        url1: First URL
        url2: Second URL
        
    Returns:
        True if same domain, False otherwise
    """
    parsed1 = urllib.parse.urlparse(url1)
    parsed2 = urllib.parse.urlparse(url2)
    
    return parsed1.netloc.lower() == parsed2.netloc.lower()

def extract_domain(url: str) -> str:
    """
    Extract domain from URL
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain name
    """
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc.lower()

def generate_id(prefix: str = '') -> str:
    """
    Generate a unique ID
    
    Args:
        prefix: Optional prefix for the ID
        
    Returns:
        Unique ID string
    """
    timestamp = datetime.datetime.now().isoformat()
    random_part = hashlib.md5(timestamp.encode()).hexdigest()[:8]
    
    if prefix:
        return f"{prefix}-{random_part}"
    return random_part

def truncate_text(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate text to maximum length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def safe_json_loads(text: str, default: Any = None) -> Any:
    """
    Safely load JSON with error handling
    
    Args:
        text: JSON string to parse
        default: Default value if parsing fails
        
    Returns:
        Parsed JSON or default
    """
    try:
        return json.loads(text)
    except:
        return default

def clean_html(html: str) -> str:
    """
    Clean HTML by removing extra whitespace
    
    Args:
        html: HTML string to clean
        
    Returns:
        Cleaned HTML
    """
    # Remove extra whitespace
    html = re.sub(r'\s+', ' ', html)
    # Remove spaces between tags
    html = re.sub(r'>\s+<', '><', html)
    return html.strip()

def extract_scripts(html: str) -> List[str]:
    """
    Extract JavaScript code from HTML
    
    Args:
        html: HTML string
        
    Returns:
        List of JavaScript code snippets
    """
    scripts = []
    
    # Extract inline scripts
    inline_pattern = r'<script[^>]*>(.*?)</script>'
    inline_matches = re.findall(inline_pattern, html, re.IGNORECASE | re.DOTALL)
    scripts.extend([s.strip() for s in inline_matches if s.strip()])
    
    # Extract event handlers
    event_pattern = r'on\w+\s*=\s*["\']([^"\']*)["\']'
    event_matches = re.findall(event_pattern, html, re.IGNORECASE)
    scripts.extend([s.strip() for s in event_matches if s.strip()])
    
    return scripts

def encode_base64(text: str) -> str:
    """
    Encode text to base64
    
    Args:
        text: Text to encode
        
    Returns:
        Base64 encoded string
    """
    import base64
    return base64.b64encode(text.encode()).decode()

def decode_base64(encoded: str) -> str:
    """
    Decode base64 text
    
    Args:
        encoded: Base64 encoded string
        
    Returns:
        Decoded text
    """
    import base64
    try:
        return base64.b64decode(encoded).decode()
    except:
        return ''

def is_url_accessible(url: str, timeout: int = 5) -> bool:
    """
    Check if a URL is accessible
    
    Args:
        url: URL to check
        timeout: Timeout in seconds
        
    Returns:
        True if accessible, False otherwise
    """
    import requests
    
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return response.status_code < 500
    except:
        return False

def format_time(seconds: float) -> str:
    """
    Format time in seconds to human readable string
    
    Args:
        seconds: Time in seconds
        
    Returns:
        Formatted time string
    """
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"

def merge_dicts(dict1: Dict, dict2: Dict, deep: bool = True) -> Dict:
    """
    Merge two dictionaries
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        deep: Deep merge or shallow
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if deep and key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value, deep)
        else:
            result[key] = value
    
    return result