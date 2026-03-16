#!/usr/bin/env python3
"""
Sophisticated confidence scoring system for vulnerability validation
"""

import re
from typing import Dict, Any, List, Tuple
import logging

class ConfidenceScorer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Evidence weights
        self.evidence_weights = {
            'payload_execution': 0.35,      # Script actually executed
            'payload_reflection': 0.25,      # Payload appears in response
            'context_dangerous': 0.20,       # In dangerous context (script, event handler)
            'no_encoding': 0.10,              # Input wasn't sanitized
            'context_breakout': 0.10           # Broke out of attribute/script
        }
        
        # Penalties
        self.penalties = {
            'html_encoding': -0.20,
            'html_entity': -0.15,
            'url_encoding': -0.10,
            'backslash_escaping': -0.15,
            'waf_keyword_filter': -0.25,
            'truncated_input': -0.30
        }
        
        # Confidence thresholds
        self.thresholds = {
            'critical': 90,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        
    def calculate_confidence(self, response_html: str, payload: str, 
                            context: Dict[str, Any], 
                            ai_analysis: Dict[str, Any] = None) -> Tuple[int, List[str], str]:
        """
        Calculate confidence score for a potential vulnerability
        
        Args:
            response_html: The HTML response from the server
            payload: The payload that was sent
            context: Context analysis from ContextDetector
            ai_analysis: Optional AI analysis results
            
        Returns:
            Tuple of (confidence_score, evidence_list, severity_level)
        """
        score = 0
        evidence = []
        
        # Check 1: Payload Execution Evidence
        execution_score, execution_evidence = self._check_payload_execution(response_html, payload)
        score += execution_score * self.evidence_weights['payload_execution']
        evidence.extend(execution_evidence)
        
        # Check 2: Payload Reflection
        reflection_score, reflection_evidence = self._check_payload_reflection(response_html, payload)
        score += reflection_score * self.evidence_weights['payload_reflection']
        evidence.extend(reflection_evidence)
        
        # Check 3: Context Danger Level
        context_score, context_evidence = self._assess_context_danger(context)
        score += context_score * self.evidence_weights['context_dangerous']
        evidence.extend(context_evidence)
        
        # Check 4: Encoding Status
        encoding_score, encoding_evidence = self._check_encoding_status(context)
        score += encoding_score * self.evidence_weights['no_encoding']
        evidence.extend(encoding_evidence)
        
        # Check 5: Context Breakout
        breakout_score, breakout_evidence = self._check_context_breakout(response_html, payload, context)
        score += breakout_score * self.evidence_weights['context_breakout']
        evidence.extend(breakout_evidence)
        
        # Apply penalties based on context
        penalty_score, penalty_evidence = self._apply_penalties(response_html, context)
        score += penalty_score  # Penalties are negative
        evidence.extend(penalty_evidence)
        
        # Incorporate AI analysis if available
        if ai_analysis:
            ai_score, ai_evidence = self._incorporate_ai_analysis(ai_analysis)
            score = (score * 0.7) + (ai_score * 0.3)  # 70% heuristics, 30% AI
            evidence.append(f"AI validation: {ai_analysis.get('explanation', '')[:100]}...")
        
        # Normalize score to 0-100
        final_score = min(max(int(score * 100), 0), 100)
        
        # Determine severity
        severity = self._determine_severity(final_score, context)
        
        return final_score, evidence, severity
    
    def _check_payload_execution(self, html: str, payload: str) -> Tuple[float, List[str]]:
        """Check for evidence that payload actually executed"""
        score = 0
        evidence = []
        
        # Look for JavaScript execution indicators
        execution_patterns = [
            (r'alert\s*\(\s*[\'"]XSS[\'"]\s*\)', "JavaScript alert() function present"),
            (r'confirm\s*\(\s*[\'"]XSS[\'"]\s*\)', "JavaScript confirm() function present"),
            (r'prompt\s*\(\s*[\'"]XSS[\'"]\s*\)', "JavaScript prompt() function present"),
            (r'console\.log\s*\(\s*[\'"]XSS[\'"]\s*\)', "Console logging present"),
            (r'document\.cookie', "Document.cookie access detected"),
            (r'window\.location', "Window.location manipulation detected"),
            (r'<script>.*?</script>', "Script tags executed"),
            (r'on\w+\s*=', "Event handler executed")
        ]
        
        for pattern, desc in execution_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.3
                evidence.append(desc)
                
        # Check if payload appears multiple times (possible DOM manipulation)
        if html.count(payload) > 2:
            score += 0.2
            evidence.append("Payload appears multiple times - possible DOM manipulation")
            
        return min(score, 1.0), evidence
    
    def _check_payload_reflection(self, html: str, payload: str) -> Tuple[float, List[str]]:
        """Check how the payload is reflected"""
        score = 0
        evidence = []
        
        if payload in html:
            score += 0.5
            evidence.append("Payload directly reflected in response")
            
            # Check reflection position (early in response is more dangerous)
            position_ratio = html.find(payload) / len(html)
            if position_ratio < 0.3:
                score += 0.3
                evidence.append("Payload reflected early in response - higher impact")
                
            # Check reflection without modification
            if html.count(payload) == html.lower().count(payload.lower()):
                score += 0.2
                evidence.append("Payload reflected exactly as sent - no modification")
                
        return min(score, 1.0), evidence
    
    def _assess_context_danger(self, context: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Assess how dangerous the context is"""
        score = 0
        evidence = []
        
        location = context.get('location', 'unknown')
        context_safety = context.get('context_safety', 'unknown')
        
        # Score based on location
        dangerous_locations = {
            'script': 0.9,
            'attribute': 0.7,
            'comment': 0.3,
            'style': 0.4,
            'text': 0.2
        }
        
        if location in dangerous_locations:
            score += dangerous_locations[location]
            evidence.append(f"Payload in {location} context - {'very dangerous' if dangerous_locations[location] > 0.7 else 'moderately dangerous'}")
        
        # Check specific dangerous attributes
        if location == 'attribute':
            attr = context.get('attribute_name', '')
            if attr in ['href', 'src', 'data']:
                score += 0.2
                evidence.append(f"Dangerous attribute: {attr}")
            elif attr.startswith('on'):
                score += 0.3
                evidence.append(f"Event handler attribute: {attr} - can execute JavaScript")
                
        # Context safety assessment
        if context_safety == 'high_risk':
            score += 0.2
            evidence.append("Context assessed as high risk for exploitation")
            
        return min(score, 1.0), evidence
    
    def _check_encoding_status(self, context: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Check if payload was encoded/sanitized"""
        score = 0
        evidence = []
        
        if not context.get('is_encoded', True):
            score += 0.8
            evidence.append("No encoding detected - payload passed through unchanged")
        else:
            encoding_type = context.get('encoding_type', 'unknown')
            evidence.append(f"Encoding detected: {encoding_type} - reduces exploitability")
            
        if not context.get('is_filtered', True):
            score += 0.2
            evidence.append("No filtering detected - payload fully intact")
            
        return min(score, 1.0), evidence
    
    def _check_context_breakout(self, html: str, payload: str, 
                                context: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Check if payload broke out of its context"""
        score = 0
        evidence = []
        
        location = context.get('location', '')
        
        if location == 'attribute':
            # Check if payload closed the attribute and added new ones
            if f'"{payload}' in html or f"'{payload}" in html:
                if 'on' in payload or '=' in payload:
                    score += 0.8
                    evidence.append("Payload broke out of attribute context - can add new attributes")
                    
        elif location == 'script':
            # Check if payload closed script tag
            if '</script>' in payload.lower() and '<script>' in html:
                score += 0.9
                evidence.append("Payload broke out of script context - can inject new scripts")
                
        elif location == 'comment':
            if '-->' in payload:
                score += 0.7
                evidence.append("Payload broke out of HTML comment")
                
        return min(score, 1.0), evidence
    
    def _apply_penalties(self, html: str, context: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Apply penalties based on security measures detected"""
        penalty = 0
        evidence = []
        
        # Check for various encoding patterns
        encoding_patterns = [
            ('&lt;|&gt;|&amp;|&quot;|&#x', 'html_entity', -0.15),
            ('%3C|%3E|%22|%27|%2F', 'url_encoding', -0.10),
            ('\\\\u003c|\\\\u003e|\\\\u0022', 'unicode_escape', -0.15),
            ('\\\\x3c|\\\\x3e|\\\\x22', 'hex_encoding', -0.15),
            ('\\\\[\\\'"\\\\]', 'backslash_escaping', -0.15)
        ]
        
        for pattern, penalty_type, penalty_value in encoding_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                penalty += penalty_value
                evidence.append(f"Penalty: {penalty_type} detected")
                
        # Check for WAF keywords
        waf_patterns = [
            'blocked', 'rejected', 'forbidden', 'attack detected',
            'security', 'firewall', 'waf', 'mod_security'
        ]
        
        for pattern in waf_patterns:
            if pattern in html.lower():
                penalty += -0.25
                evidence.append(f"Penalty: WAF keyword '{pattern}' detected")
                break
                
        return penalty, evidence
    
    def _incorporate_ai_analysis(self, ai_analysis: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Incorporate AI analysis into confidence score"""
        score = 0
        evidence = []
        
        if ai_analysis.get('is_vulnerable', False):
            score += ai_analysis.get('confidence', 50) / 100
            evidence.append("AI model confirms vulnerability")
            
            # Adjust based on false positive risk
            fp_risk = ai_analysis.get('false_positive_risk', 'medium')
            if fp_risk == 'low':
                score += 0.2
            elif fp_risk == 'high':
                score -= 0.2
        else:
            score += 0.2  # AI says not vulnerable, but we keep some confidence in heuristics
            evidence.append("AI model suggests false positive - verify manually")
            
        return min(score, 1.0), evidence
    
    def _determine_severity(self, score: int, context: Dict[str, Any]) -> str:
        """Determine severity level based on score and context"""
        if score >= self.thresholds['critical']:
            return 'CRITICAL'
        elif score >= self.thresholds['high']:
            return 'HIGH'
        elif score >= self.thresholds['medium']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_recommendations(self, score: int, severity: str, 
                           context: Dict[str, Any]) -> List[str]:
        """Generate remediation recommendations based on findings"""
        recommendations = []
        
        if severity in ['CRITICAL', 'HIGH']:
            recommendations.append("🔴 IMMEDIATE ACTION REQUIRED")
            recommendations.append("  - Implement proper output encoding for all user input")
            recommendations.append("  - Use Content Security Policy (CSP) headers")
            recommendations.append("  - Apply context-specific escaping")
            
            if context.get('location') == 'script':
                recommendations.append("  - Never insert user input directly into script blocks")
            elif context.get('location') == 'attribute':
                recommendations.append("  - Validate and sanitize all attribute values")
                
        elif severity == 'MEDIUM':
            recommendations.append("🟡 Review and fix within normal development cycle")
            recommendations.append("  - Implement input validation")
            recommendations.append("  - Use parameterized queries where applicable")
            
        else:
            recommendations.append("🟢 Low priority - verify during next security review")
            recommendations.append("  - Monitor for similar patterns")
            
        return recommendations