#!/usr/bin/env python3
"""
AI-powered response analyzer using local LLM (Ollama)
"""

import requests
import json
import logging
from typing import Dict, Any, Optional, List
import time
from tenacity import retry, stop_after_attempt, wait_exponential

class AIAnalyzer:
    def __init__(self, model: str = "llama2", 
                 ollama_url: str = "http://localhost:11434",
                 timeout: int = 30):
        """
        Initialize AI analyzer with local Ollama instance
        
        Args:
            model: Ollama model to use
            ollama_url: URL of Ollama API
            timeout: Request timeout in seconds
        """
        self.model = model
        self.ollama_url = ollama_url
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Cache for analyses to avoid repeated calls
        self.cache = {}
        self.cache_size = 100
        
        # Stats tracking
        self.stats = {
            'total_analyses': 0,
            'cache_hits': 0,
            'avg_response_time': 0,
            'failures': 0
        }
        
    def check_ollama_available(self) -> bool:
        """Check if Ollama is running and accessible"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                self.logger.info(f"Ollama available with {len(models)} models")
                return True
        except:
            self.logger.warning("Ollama not available, falling back to heuristic analysis")
            return False
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def analyze_xss_response(self, original_response: str, payload: str,
                            response_html: str, status_code: int,
                            context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Send response to AI for intelligent vulnerability analysis
        
        Args:
            original_response: Original response before payload
            payload: Payload that was sent
            response_html: HTML response after payload
            status_code: HTTP status code
            context: Additional context information
            
        Returns:
            Dictionary with AI analysis results
        """
        start_time = time.time()
        
        # Generate cache key
        cache_key = self._generate_cache_key(payload, response_html[:500])
        
        # Check cache
        if cache_key in self.cache:
            self.stats['cache_hits'] += 1
            return self.cache[cache_key]
        
        self.stats['total_analyses'] += 1
        
        # Truncate response to avoid token limits
        truncated_html = response_html[:3000] if len(response_html) > 3000 else response_html
        
        # Prepare context for AI
        context_str = self._prepare_context_string(context)
        
        prompt = f"""You are an expert web application security analyst. Analyze this HTTP response for XSS vulnerabilities.

CONTEXT INFORMATION:
{context_str}

ORIGINAL INPUT (what was sent): {original_response[:200]}
TEST PAYLOAD: {payload}
STATUS CODE: {status_code}

RESPONSE SNIPPET (what came back):
{truncated_html}

TASK:
Analyze if this is a genuine XSS vulnerability or a false positive. Consider:

1. Is the payload reflected in the response? How?
2. Is it reflected in a dangerous context (script, event handler, attribute)?
3. Is there any evidence of filtering/encoding/sanitization?
4. Could this be exploited in a real attack?
5. What type of XSS is it (reflected, stored, DOM-based)?

Provide your analysis in valid JSON format with these exact keys:
- is_vulnerable (boolean): true if you believe this is a real vulnerability
- confidence (0-100): your confidence level
- vulnerability_type (string): "reflected", "stored", "dom", or "none"
- exploitation_difficulty (string): "easy", "medium", "hard", or "impossible"
- evidence (string): specific evidence from the response
- waf_detected (boolean): true if you see signs of WAF/IDS
- recommendation (string): brief remediation advice
- explanation (string): detailed explanation of your reasoning
- false_positive_risk (string): "low", "medium", "high" - risk this is a false positive

Return ONLY the JSON object, no other text.
"""

        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {
                        "temperature": 0.1,  # Low temperature for consistency
                        "num_predict": 1024   # Limit response length
                    }
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                try:
                    # Parse AI response
                    ai_response_text = result.get('response', '{}')
                    
                    # Clean the response (sometimes models add extra text)
                    ai_response_text = self._clean_json_response(ai_response_text)
                    
                    ai_analysis = json.loads(ai_response_text)
                    
                    # Validate required fields
                    ai_analysis = self._validate_analysis(ai_analysis)
                    
                    # Add metadata
                    ai_analysis['model_used'] = self.model
                    ai_analysis['analysis_time'] = time.time() - start_time
                    
                    # Cache the result
                    self._add_to_cache(cache_key, ai_analysis)
                    
                    # Update stats
                    self._update_stats(start_time)
                    
                    return ai_analysis
                    
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse AI response as JSON: {e}")
                    return self._fallback_analysis(response_html, payload)
            else:
                self.logger.error(f"Ollama API error: {response.status_code}")
                return self._fallback_analysis(response_html, payload)
                
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            self.stats['failures'] += 1
            return self._fallback_analysis(response_html, payload)
    
    def _prepare_context_string(self, context: Optional[Dict]) -> str:
        """Prepare context information for the prompt"""
        if not context:
            return "No additional context provided."
            
        context_str = ""
        if context.get('location'):
            context_str += f"- Payload appears in: {context['location']}\n"
        if context.get('is_encoded'):
            context_str += f"- Encoding detected: {context.get('encoding_type', 'unknown')}\n"
        if context.get('tag_name'):
            context_str += f"- HTML tag: {context['tag_name']}\n"
        if context.get('attribute_name'):
            context_str += f"- HTML attribute: {context['attribute_name']}\n"
            
        return context_str if context_str else "No specific context detected."
    
    def _generate_cache_key(self, payload: str, response_snippet: str) -> str:
        """Generate cache key for analysis"""
        import hashlib
        combined = f"{payload}:{response_snippet}"
        return hashlib.md5(combined.encode()).hexdigest()
    
    def _add_to_cache(self, key: str, value: Dict):
        """Add item to cache, managing size"""
        self.cache[key] = value
        
        # Trim cache if too large
        if len(self.cache) > self.cache_size:
            # Remove oldest items
            items = list(self.cache.items())
            self.cache = dict(items[-self.cache_size:])
    
    def _clean_json_response(self, text: str) -> str:
        """Clean AI response to extract valid JSON"""
        # Remove markdown code blocks
        text = text.replace('```json', '').replace('```', '')
        
        # Find JSON object boundaries
        start = text.find('{')
        end = text.rfind('}') + 1
        
        if start != -1 and end > start:
            return text[start:end]
        
        return text
    
    def _validate_analysis(self, analysis: Dict) -> Dict:
        """Ensure all required fields are present"""
        required_fields = {
            'is_vulnerable': False,
            'confidence': 50,
            'vulnerability_type': 'unknown',
            'exploitation_difficulty': 'unknown',
            'evidence': 'No evidence provided',
            'waf_detected': False,
            'recommendation': 'Further manual testing required',
            'explanation': 'AI analysis could not determine with certainty',
            'false_positive_risk': 'medium'
        }
        
        for field, default in required_fields.items():
            if field not in analysis:
                analysis[field] = default
                
        return analysis
    
    def _update_stats(self, start_time: float):
        """Update performance statistics"""
        response_time = time.time() - start_time
        
        # Update rolling average
        total = self.stats['total_analyses']
        current_avg = self.stats['avg_response_time']
        self.stats['avg_response_time'] = (current_avg * (total - 1) + response_time) / total
    
    def _fallback_analysis(self, response_html: str, payload: str) -> Dict[str, Any]:
        """Fallback heuristic analysis when AI is unavailable"""
        self.logger.info("Using fallback heuristic analysis")
        
        analysis = {
            'is_vulnerable': False,
            'confidence': 0,
            'vulnerability_type': 'none',
            'exploitation_difficulty': 'unknown',
            'waf_detected': False,
            'false_positive_risk': 'medium'
        }
        
        # Simple heuristic checks
        evidence = []
        
        # Check if payload is reflected
        if payload in response_html:
            analysis['is_vulnerable'] = True
            analysis['confidence'] = 60
            analysis['vulnerability_type'] = 'reflected'
            evidence.append("Payload reflected in response")
        
        # Check for script execution indicators
        if '<script>' in response_html.lower() and 'alert' in response_html.lower():
            analysis['is_vulnerable'] = True
            analysis['confidence'] = 80
            evidence.append("Script tags present in response")
            analysis['vulnerability_type'] = 'reflected'
        
        # Check for event handlers
        if 'onerror=' in response_html.lower() or 'onload=' in response_html.lower():
            analysis['is_vulnerable'] = True
            analysis['confidence'] = 75
            evidence.append("Event handlers present in response")
        
        # Check for encoding
        if '&lt;' in response_html or '&gt;' in response_html:
            analysis['waf_detected'] = True
            evidence.append("HTML encoding detected - possible WAF/filtering")
            analysis['confidence'] = max(0, analysis['confidence'] - 20)
        
        analysis['evidence'] = ', '.join(evidence) if evidence else "No clear evidence found"
        analysis['explanation'] = "Heuristic analysis performed (AI unavailable)"
        analysis['recommendation'] = "Manual verification recommended"
        
        return analysis
    
    def batch_analyze(self, analyses: List[Dict]) -> Dict[str, Any]:
        """
        Analyze a batch of results for patterns and insights
        
        Args:
            analyses: List of individual analysis results
            
        Returns:
            Batch analysis with patterns and recommendations
        """
        if not analyses:
            return {'message': 'No analyses to process'}
            
        true_positives = sum(1 for a in analyses if a.get('is_vulnerable', False))
        false_positives = len(analyses) - true_positives
        
        waf_detected = any(a.get('waf_detected', False) for a in analyses)
        
        # Group by vulnerability type
        vuln_types = {}
        for a in analyses:
            vtype = a.get('vulnerability_type', 'unknown')
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        avg_confidence = sum(a.get('confidence', 0) for a in analyses) / len(analyses)
        
        return {
            'total_analyzed': len(analyses),
            'potential_vulnerabilities': true_positives,
            'false_positives_flagged': false_positives,
            'waf_detected': waf_detected,
            'vulnerability_types': vuln_types,
            'average_confidence': round(avg_confidence, 2),
            'recommendations': self._generate_batch_recommendations(analyses)
        }
    
    def _generate_batch_recommendations(self, analyses: List[Dict]) -> List[str]:
        """Generate recommendations based on batch analysis"""
        recommendations = []
        
        if any(a.get('waf_detected') for a in analyses):
            recommendations.append("WAF detected - use encoding variations and WAF bypass techniques")
        
        if any(a.get('vulnerability_type') == 'stored' for a in analyses):
            recommendations.append("Stored XSS detected - check database and persistent storage")
        
        avg_conf = sum(a.get('confidence', 0) for a in analyses) / len(analyses)
        if avg_conf < 50:
            recommendations.append("Low confidence scores - manual verification strongly recommended")
        
        return recommendations
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return {
            **self.stats,
            'cache_size': len(self.cache),
            'model': self.model
        }