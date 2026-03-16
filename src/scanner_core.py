#!/usr/bin/env python3
"""
Core scanner engine for AI-Enhanced Security Scanner
Handles HTTP requests, form discovery, and basic scanning logic
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import time
import logging
from typing import List, Dict, Any, Optional
import random

class SecurityScanner:
    def __init__(self, target_url: str, config: Dict[str, Any] = None):
        """
        Initialize the security scanner
        
        Args:
            target_url: The target URL to scan
            config: Configuration dictionary with settings
        """
        self.target_url = target_url
        self.config = config or {}
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Configure session with realistic browser headers
        self.session = requests.Session()
        self.session.headers.update(self._generate_headers())
        
        # Scanner state
        self.forms = []
        self.urls = []
        self.vulnerabilities = []
        self.scan_id = self._generate_scan_id()
        
        # Rate limiting
        self.delay = self.config.get('request_delay', 0.5)
        self.max_retries = self.config.get('max_retries', 3)
        
        self.logger.info(f"Scanner initialized for target: {target_url}")
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(f"Scanner-{random.randint(1000, 9999)}")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def _generate_headers(self) -> Dict[str, str]:
        """Generate realistic browser headers"""
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        import hashlib
        import datetime
        
        scan_string = f"{self.target_url}{datetime.datetime.now().isoformat()}"
        return hashlib.md5(scan_string.encode()).hexdigest()[:8]
    
    def discover_forms(self) -> List[Dict[str, Any]]:
        """
        Discover all forms on the target website
        
        Returns:
            List of form details dictionaries
        """
        self.logger.info(f"Discovering forms on {self.target_url}")
        
        try:
            response = self._make_request(self.target_url)
            if not response:
                return []
            
            # Use html.parser instead of lxml
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            self.logger.info(f"Found {len(forms)} forms")
            
            for form in forms:
                form_details = self._extract_form_details(form)
                if form_details['inputs']:  # Only add forms with inputs
                    self.forms.append(form_details)
                    
            return self.forms
            
        except Exception as e:
            self.logger.error(f"Error discovering forms: {e}")
            return []
    
    def _extract_form_details(self, form) -> Dict[str, Any]:
        """Extract detailed information from a form element"""
        details = {
            'action': urljoin(self.target_url, form.get('action', '')),
            'method': form.get('method', 'get').lower(),
            'inputs': [],
            'id': form.get('id', ''),
            'name': form.get('name', ''),
            'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
        }
        
        # Extract all input fields
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_details = self._extract_input_details(input_tag)
            if input_details:
                details['inputs'].append(input_details)
        
        return details
    
    def _extract_input_details(self, input_tag) -> Optional[Dict[str, Any]]:
        """Extract details from an input element"""
        input_type = input_tag.get('type', 'text').lower()
        input_name = input_tag.get('name')
        
        # Skip submit buttons and fields without names
        if not input_name or input_type in ['submit', 'button', 'reset']:
            return None
            
        return {
            'name': input_name,
            'type': input_type,
            'value': input_tag.get('value', ''),
            'required': input_tag.has_attr('required'),
            'maxlength': input_tag.get('maxlength'),
            'pattern': input_tag.get('pattern')
        }
    
    def _make_request(self, url: str, method: str = 'GET', 
                     data: Dict = None, params: Dict = None,
                     retry_count: int = 0) -> Optional[requests.Response]:
        """
        Make HTTP request with retry logic and rate limiting
        
        Args:
            url: Request URL
            method: HTTP method
            data: POST data
            params: URL parameters
            retry_count: Current retry attempt
            
        Returns:
            Response object or None on failure
        """
        try:
            # Rate limiting
            time.sleep(self.delay)
            
            if method.lower() == 'post':
                response = self.session.post(url, data=data, params=params, timeout=10)
            else:
                response = self.session.get(url, params=params, timeout=10)
            
            # Check for rate limiting
            if response.status_code == 429:
                wait_time = int(response.headers.get('Retry-After', 60))
                self.logger.warning(f"Rate limited. Waiting {wait_time} seconds")
                time.sleep(wait_time)
                return self._make_request(url, method, data, params, retry_count)
            
            return response
            
        except requests.exceptions.RequestException as e:
            if retry_count < self.max_retries:
                self.logger.warning(f"Request failed, retrying ({retry_count + 1}/{self.max_retries})")
                time.sleep(2 ** retry_count)  # Exponential backoff
                return self._make_request(url, method, data, params, retry_count + 1)
            else:
                self.logger.error(f"Request failed after {self.max_retries} retries: {e}")
                return None
    
    def crawl(self, max_pages: int = 10) -> List[str]:
        """
        Simple crawler to discover URLs on the target site
        
        Args:
            max_pages: Maximum number of pages to crawl
            
        Returns:
            List of discovered URLs
        """
        self.logger.info(f"Starting crawl (max pages: {max_pages})")
        
        to_visit = [self.target_url]
        visited = set()
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
                
            self.logger.debug(f"Crawling: {url}")
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                visited.add(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, link['href'])
                    
                    # Only follow links to same domain
                    if (urlparse(absolute_url).netloc == urlparse(self.target_url).netloc
                        and absolute_url not in visited
                        and absolute_url not in to_visit):
                        to_visit.append(absolute_url)
        
        self.urls = list(visited)
        self.logger.info(f"Crawl complete. Found {len(self.urls)} unique URLs")
        return self.urls