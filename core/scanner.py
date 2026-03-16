# core/scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import logging
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor

class NeuroXSScanner:  # Make sure this name matches
    def __init__(self, target_url: str, threads: int = 3, delay: float = 0.5):
        self.target_url = target_url
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NeuroXSS-AI-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Results storage
        self.vulnerabilities = []
        self.scanned_urls = set()
        
    def discover_endpoints(self) -> List[Dict]:
        """Discover all potential input points"""
        endpoints = []
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms
            forms = soup.find_all('form')
            for form in forms:
                form_info = self._extract_form_info(form)
                if form_info['inputs']:
                    endpoints.append({
                        'type': 'form',
                        'method': form_info['method'],
                        'action': urljoin(self.target_url, form_info['action']),
                        'inputs': form_info['inputs']
                    })
            
            # Find URL parameters
            parsed = urlparse(self.target_url)
            if parsed.query:
                params = parsed.query.split('&')
                param_list = []
                for p in params:
                    if '=' in p:
                        param_list.append(p.split('=')[0])
                if param_list:
                    endpoints.append({
                        'type': 'url_params',
                        'url': self.target_url,
                        'params': param_list
                    })
            
            self.logger.info(f"Discovered {len(endpoints)} endpoints")
            return endpoints
            
        except Exception as e:
            self.logger.error(f"Error discovering endpoints: {e}")
            return []
    
    def _extract_form_info(self, form) -> Dict:
        """Extract information from a form"""
        info = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        
        for input_tag in form.find_all(['input', 'textarea']):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name')
            if input_name and input_type not in ['submit', 'button', 'image']:
                info['inputs'].append({
                    'name': input_name,
                    'type': input_type
                })
        
        return info