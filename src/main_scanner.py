#!/usr/bin/env python3
"""
Main scanner integrating all components
"""

import argparse
import sys
import json
import yaml
import os
from typing import Dict, Any, List
import logging
from datetime import datetime

from scanner_core import SecurityScanner
from payload_generator import XSSPayloadGenerator
from context_detector import ContextDetector
from ai_analyzer import AIAnalyzer
from confidence_scorer import ConfidenceScorer
from report_generator import ReportGenerator

class AIEnhancedScanner:
    def __init__(self, target_url: str, config_file: str = None):
        """
        Initialize the AI-Enhanced Security Scanner
        
        Args:
            target_url: Target URL to scan
            config_file: Optional configuration file
        """
        self.target_url = target_url
        self.config = self._load_config(config_file)
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Initialize components
        self.scanner = SecurityScanner(target_url, self.config.get('scanner', {}))
        self.payload_gen = XSSPayloadGenerator(self.config.get('payloads', {}))
        self.context_detector = ContextDetector()
        self.confidence_scorer = ConfidenceScorer()
        
        # Initialize AI if enabled
        self.use_ai = self.config.get('ai', {}).get('enabled', True)
        if self.use_ai:
            self.ai_analyzer = AIAnalyzer(
                model=self.config.get('ai', {}).get('model', 'llama2'),
                ollama_url=self.config.get('ai', {}).get('ollama_url', 'http://localhost:11434')
            )
            # Check if Ollama is available
            if not self.ai_analyzer.check_ollama_available():
                self.logger.warning("Ollama not available, falling back to heuristic analysis")
                self.use_ai = False
        
        self.report_gen = ReportGenerator(company_name="Grae-X Labs")
        
        # Results storage
        self.results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'pages_scanned': 0,
            'forms_tested': 0,
            'vulnerabilities': [],
            'ai_analyses': [],
            'scan_duration': 0
        }
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('AI-Enhanced-Scanner')
        logger.setLevel(logging.INFO)
        
        # Console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _load_config(self, config_file: str = None) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            'scanner': {
                'request_delay': 0.5,
                'max_retries': 3,
                'max_pages': 20
            },
            'ai': {
                'enabled': True,
                'model': 'llama2',
                'ollama_url': 'http://localhost:11434',
                'timeout': 30
            },
            'payloads': {
                'intensity': 'medium',
                'custom_payloads': []
            },
            'reporting': {
                'format': 'html',
                'include_ai_insights': True,
                'include_raw_data': False
            }
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                # Merge configs
                for key, value in user_config.items():
                    if key in default_config:
                        default_config[key].update(value)
        
        return default_config
    
    def run_scan(self) -> Dict[str, Any]:
        """Execute the complete security scan"""
        import time
        start_time = time.time()
        
        self.logger.info("=" * 60)
        self.logger.info(f"🚀 AI-Enhanced Security Scanner v1.0")
        self.logger.info(f"🎯 Target: {self.target_url}")
        self.logger.info(f"🤖 AI Analysis: {'Enabled' if self.use_ai else 'Disabled'}")
        self.logger.info("=" * 60)
        
        # Step 1: Crawl the target
        self.logger.info("\n[1/4] 🔍 Crawling target...")
        urls = self.scanner.crawl(max_pages=self.config['scanner']['max_pages'])
        self.results['pages_scanned'] = len(urls)
        self.logger.info(f"   Found {len(urls)} unique URLs")
        
        # Step 2: Discover forms
        self.logger.info("\n[2/4] 📝 Discovering forms...")
        forms = []
        for url in urls:
            scanner = SecurityScanner(url, self.config['scanner'])
            page_forms = scanner.discover_forms()
            forms.extend(page_forms)
        self.results['forms_tested'] = len(forms)
        self.logger.info(f"   Found {len(forms)} forms to test")
        
        # Step 3: Test for XSS vulnerabilities
        self.logger.info("\n[3/4] 🎯 Testing for XSS vulnerabilities...")
        
        for i, form in enumerate(forms, 1):
            self.logger.info(f"   Testing form {i}/{len(forms)}: {form['action']}")
            
            # Generate payloads based on form context
            payloads = self.payload_gen.generate_payloads(self.config['payloads']['intensity'])
            
            for payload in payloads:
                # Prepare form data
                form_data = {}
                for input_field in form['inputs']:
                    form_data[input_field['name']] = payload
                
                # Submit form
                response = self.scanner._make_request(
                    form['action'],
                    method=form['method'],
                    data=form_data if form['method'] == 'post' else None,
                    params=form_data if form['method'] == 'get' else None
                )
                
                if response:
                    # Debug: Check response
                    self.logger.info(f"      Response status: {response.status_code}")
                    self.logger.info(f"      Testing payload: {payload[:50]}...")
                    
                    # Check if payload is in response
                    if payload in response.text:
                        self.logger.info(f"      ✅ Payload FOUND in response!")
                    else:
                        self.logger.info(f"      ❌ Payload NOT found in response")
                    
                    # Analyze context
                    context = self.context_detector.analyze_response(
                        response.text, 
                        list(form_data.keys())[0] if form_data else 'unknown',
                        payload
                    )
                    
                    # Get AI analysis if available
                    ai_analysis = None
                    if self.use_ai:
                        ai_analysis = self.ai_analyzer.analyze_xss_response(
                            original_response="Form submission",
                            payload=payload,
                            response_html=response.text,
                            status_code=response.status_code,
                            context=context
                        )
                        self.results['ai_analyses'].append({
                            'payload': payload,
                            'analysis': ai_analysis
                        })
                    
                    # Calculate confidence score
                    confidence, evidence, severity = self.confidence_scorer.calculate_confidence(
                        response.text,
                        payload,
                        context,
                        ai_analysis
                    )
                    
                    # Debug: Show confidence
                    self.logger.info(f"      Confidence score: {confidence}% ({severity})")
                    
                    # If confidence is high enough, record vulnerability
                    if confidence >= 20:  # Lowered threshold to catch everything
                        vulnerability = {
                            'type': 'XSS',
                            'payload': payload,
                            'location': form['action'],
                            'parameter': list(form_data.keys())[0] if form_data else 'unknown',
                            'confidence': confidence,
                            'severity': severity,
                            'evidence': ' | '.join(evidence[:3]) if evidence else 'No evidence',
                            'description': f"Potential XSS vulnerability detected in form at {form['action']}",
                            'recommendation': 'Implement proper output encoding',
                            'waf_detected': context.get('waf_detected', False),
                            'exploitation_difficulty': ai_analysis.get('exploitation_difficulty', 'unknown') if ai_analysis else 'unknown'
                        }
                        
                        if ai_analysis and 'explanation' in ai_analysis:
                            vulnerability['ai_explanation'] = ai_analysis['explanation']
                        
                        self.results['vulnerabilities'].append(vulnerability)
                        
                        self.logger.info(f"      ⚠️  Found potential vulnerability! Confidence: {confidence}% ({severity})")
        
        # Step 4: Generate report
        self.logger.info("\n[4/4] 📊 Generating report...")
        
        # Calculate scan duration
        self.results['scan_duration'] = round(time.time() - start_time, 2)
        
        # Generate report
        report_file = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        self.report_gen.generate_html_report(self.results, report_file)
        
        # Print summary
        self.logger.info("\n" + "=" * 60)
        self.logger.info("✅ SCAN COMPLETE")
        self.logger.info("=" * 60)
        self.logger.info(f"📊 Results Summary:")
        self.logger.info(f"   Pages scanned: {self.results['pages_scanned']}")
        self.logger.info(f"   Forms tested: {self.results['forms_tested']}")
        self.logger.info(f"   Vulnerabilities found: {len(self.results['vulnerabilities'])}")
        
        # Count by severity
        severity_counts = {}
        for v in self.results['vulnerabilities']:
            sev = v['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                self.logger.info(f"      {severity}: {severity_counts[severity]}")
        
        self.logger.info(f"\n📄 Report saved to: {report_file}")
        self.logger.info("=" * 60)
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description='AI-Enhanced Security Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--config', '-c', help='Configuration file (YAML)')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI analysis')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], 
                       default='medium', help='Scan intensity')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = AIEnhancedScanner(args.target, args.config)
    
    # Override config with command line arguments
    if args.no_ai:
        scanner.config['ai']['enabled'] = False
    if args.intensity:
        scanner.config['payloads']['intensity'] = args.intensity
    
    try:
        # Run the scan
        results = scanner.run_scan()
        
        # Save raw results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n📁 Raw results saved to: {args.output}")
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()