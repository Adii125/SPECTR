"""Cross-Site Scripting (XSS) detector for SPECTR scanner"""

import urllib.parse
from payloads.xss_payloads import XssPayloads

class XssDetector:
    """Detects XSS vulnerabilities - Basic, Encoded, and Filter Bypass payloads only"""
    
    def __init__(self):
        self.name = "XSS"
        self.payloads = XssPayloads()
        self.reflection_markers = XssPayloads.get_reflection_markers()
    
    def detect(self, target_url, method, parameters, headers, http_client, verbose=False):
        """Detect XSS vulnerabilities with focused payload testing"""
        vulnerabilities = []
        
        if not parameters:
            if verbose:
                print(f"    [XSS] No parameters to test")
            return vulnerabilities
        
        # Get baseline response for comparison
        try:
            baseline_response = http_client.get_baseline_response(target_url, method, parameters, headers)
            baseline_content = baseline_response.text
            baseline_length = len(baseline_content)
            
            if verbose:
                print(f"    [XSS] Baseline established: {baseline_length} chars")
                
        except Exception as e:
            if verbose:
                print(f"    [XSS] Error getting baseline: {str(e)}")
            return vulnerabilities
        
        # Test each parameter for XSS
        for param_name, param_value in parameters.items():
            if verbose:
                print(f"    [XSS] Testing parameter: {param_name}")
            
            # 1. BASIC XSS PAYLOAD TESTING
            if verbose:
                print(f"      [XSS] Testing basic XSS payloads...")
            
            for payload in XssPayloads.BASIC_PAYLOADS:
                vulnerability = self._test_xss_payload(
                    target_url, method, parameters, headers, http_client,
                    param_name, payload, "basic", verbose
                )
                if vulnerability:
                    vulnerabilities.append(vulnerability)
            
            # 2. ENCODED XSS PAYLOAD TESTING
            if verbose:
                print(f"      [XSS] Testing encoded XSS payloads...")
            
            for payload in XssPayloads.ENCODED_PAYLOADS:
                vulnerability = self._test_xss_payload(
                    target_url, method, parameters, headers, http_client,
                    param_name, payload, "encoded", verbose
                )
                if vulnerability:
                    vulnerabilities.append(vulnerability)
            
            # 3. FILTER BYPASS XSS PAYLOAD TESTING
            if verbose:
                print(f"      [XSS] Testing filter bypass XSS payloads...")
            
            for payload in XssPayloads.FILTER_BYPASS:
                vulnerability = self._test_xss_payload(
                    target_url, method, parameters, headers, http_client,
                    param_name, payload, "filter_bypass", verbose
                )
                if vulnerability:
                    vulnerabilities.append(vulnerability)
        
        if verbose and vulnerabilities:
            print(f"    [XSS] Total XSS vulnerabilities found: {len(vulnerabilities)}")
            
        return vulnerabilities
    
    def _test_xss_payload(self, target_url, method, parameters, headers, http_client, 
                         param_name, payload, payload_type, verbose):
        """Test a single XSS payload and return vulnerability if found"""
        try:
            test_params = parameters.copy()
            test_params[param_name] = payload
            
            if method.upper() == 'GET':
                response = http_client.make_request(target_url, method, params=test_params, headers=headers)
            else:
                response = http_client.make_request(target_url, method, data=test_params, headers=headers)
            
            response_content = response.text
            
            # Check for payload reflection with multiple detection methods
            reflection_found, evidence = self._detect_xss_reflection(payload, response_content, payload_type)
            
            if reflection_found:
                vulnerability = {
                    'vulnerability_type': 'xss',
                    'xss_type': payload_type,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'evidence': evidence,
                    'response_snippet': response_content[:500],
                    'severity': 'MEDIUM' if payload_type == 'basic' else 'HIGH'
                }
                
                if verbose:
                    print(f"        [XSS] ✅ {payload_type.title()} XSS found: {evidence}")
                
                return vulnerability
        
        except Exception as e:
            if verbose:
                print(f"        [XSS] Error testing {payload_type} payload: {str(e)}")
        
        return None
    
    def _detect_xss_reflection(self, payload, response_content, payload_type):
        """Enhanced XSS reflection detection for basic, encoded, and filter bypass payloads"""
        evidence_found = []
        
        # 1. Direct payload reflection
        if payload in response_content:
            evidence_found.append("Direct payload reflection")
        
        # 2. Check for decoded payload reflection (for encoded payloads)
        if payload_type == "encoded":
            decoded_payload = self._decode_payload(payload)
            if decoded_payload and decoded_payload in response_content:
                evidence_found.append("Decoded payload reflection")
        
        # 3. Check for specific XSS markers
        for marker in self.reflection_markers:
            if marker.lower() in response_content.lower():
                evidence_found.append(f"XSS marker detected: {marker}")
        
        # 4. Check for script execution indicators
        script_indicators = [
            '<script', 'javascript:', 'onerror=', 'onload=', 'onclick=', 
            'alert(', 'eval(', 'SPECTR_XSS', 'prompt(', 'confirm('
        ]
        for indicator in script_indicators:
            if indicator.lower() in response_content.lower():
                # Verify it's likely from our payload
                if self._is_from_our_payload(payload, indicator, payload_type):
                    evidence_found.append(f"Script execution indicator: {indicator}")
        
        # 5. Check for HTML tag injection
        html_tags = ['<img', '<svg', '<iframe', '<object', '<embed', '<video', '<audio']
        for tag in html_tags:
            if tag.lower() in response_content.lower():
                if self._is_from_our_payload(payload, tag, payload_type):
                    evidence_found.append(f"HTML tag injection: {tag}")
        
        # Return result
        if evidence_found:
            return True, " | ".join(evidence_found)
        else:
            return False, ""
    
    def _decode_payload(self, payload):
        """Decode common payload encodings"""
        try:
            # Try URL decoding
            url_decoded = urllib.parse.unquote(payload)
            if url_decoded != payload:
                return url_decoded
            
            # Try HTML entity decoding
            import html
            html_decoded = html.unescape(payload)
            if html_decoded != payload:
                return html_decoded
            
            # Try Unicode decoding (basic)
            if '\\u' in payload:
                try:
                    unicode_decoded = payload.encode().decode('unicode_escape')
                    return unicode_decoded
                except:
                    pass
            
            return payload
        except:
            return payload
    
    def _is_from_our_payload(self, payload, indicator, payload_type):
        """Check if the indicator is likely from our payload"""
        # Simple check - look for indicator in our payload or its decoded version
        if indicator.lower() in payload.lower():
            return True
        
        # For encoded payloads, check decoded version
        if payload_type == "encoded":
            decoded = self._decode_payload(payload)
            if decoded and indicator.lower() in decoded.lower():
                return True
        
        # Check for unique markers we inject
        unique_markers = ['SPECTR_XSS', 'SPECTR_TEST']
        for marker in unique_markers:
            if marker in payload:
                return True
        
        return False
