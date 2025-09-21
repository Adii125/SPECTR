"""Server-Side Request Forgery (SSRF) detector for SPECTR scanner"""

from payloads.ssrf_payloads import SsrfPayloads

class SsrfDetector:
    """Detects SSRF vulnerabilities"""
    
    def __init__(self):
        self.name = "SSRF"
        self.payloads = SsrfPayloads()
        self.success_indicators = SsrfPayloads.get_success_indicators()
    
    def detect(self, target_url, method, parameters, headers, http_client, verbose=False):
        """Detect SSRF vulnerabilities with comprehensive testing"""
        vulnerabilities = []
        
        if not parameters:
            if verbose:
                print(f"    [SSRF] No parameters to test")
            return vulnerabilities
        
        # Get baseline response
        try:
            baseline_response = http_client.get_baseline_response(target_url, method, parameters, headers)
        except Exception as e:
            if verbose:
                print(f"    [SSRF] Error getting baseline: {str(e)}")
            return vulnerabilities
        
        #Test ALL parameters
        for param_name, param_value in parameters.items():
            if verbose:
                print(f"    [SSRF] Testing parameter: {param_name}")
            
            #Test more local network payloads
            for payload in SsrfPayloads.LOCAL_NETWORK_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = payload
                
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    
                    #Enhanced SSRF detection
                    if self._is_ssrf_successful(baseline_response, response, payload):
                        detected_indicators = self._get_detected_indicators(response.text)
                        vulnerability = {
                            'vulnerability_type': 'ssrf',
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f"SSRF detected - server accessed: {payload}. Indicators: {', '.join(detected_indicators)}",
                            'response_snippet': response.text[:500]
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"      [SSRF] Found SSRF! Payload: {payload}, Indicators: {', '.join(detected_indicators)}")
                
                except Exception as e:
                    if verbose:
                        print(f"      [SSRF] Error testing payload {payload}: {str(e)}")
                    continue
            
            #Test cloud metadata payloads
            for payload in SsrfPayloads.CLOUD_METADATA_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = payload
                
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    
                    if self._is_ssrf_successful(baseline_response, response, payload):
                        detected_indicators = self._get_detected_indicators(response.text)
                        vulnerability = {
                            'vulnerability_type': 'ssrf',
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f"SSRF to cloud metadata: {payload}. Indicators: {', '.join(detected_indicators)}",
                            'response_snippet': response.text[:500]
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"      [SSRF] Found cloud metadata SSRF! Indicators: {', '.join(detected_indicators)}")
                
                except Exception as e:
                    if verbose:
                        print(f"      [SSRF] Error testing cloud payload: {str(e)}")
                    continue
            
            #Test file protocol payloads
            for payload in SsrfPayloads.PROTOCOL_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = payload
                
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    
                    if self._is_ssrf_successful(baseline_response, response, payload):
                        detected_indicators = self._get_detected_indicators(response.text)
                        vulnerability = {
                            'vulnerability_type': 'ssrf',
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f"SSRF file access: {payload}. Indicators: {', '.join(detected_indicators)}",
                            'response_snippet': response.text[:500]
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"      [SSRF] Found file protocol SSRF! Indicators: {', '.join(detected_indicators)}")
                
                except Exception as e:
                    if verbose:
                        print(f"      [SSRF] Error testing file payload: {str(e)}")
                    continue
        
        return vulnerabilities
    
    #Enhanced SSRF detection logic
    def _is_ssrf_successful(self, baseline_response, test_response, payload):
        # Check if response is significantly different
        if test_response.text != baseline_response.text:
            # Check for SSRF indicators
            test_content_lower = test_response.text.lower()
            
            # Different response + SSRF indicators = likely SSRF
            for indicator in self.success_indicators:
                if indicator.lower() in test_content_lower:
                    return True
            
            # Even without specific indicators, significant response change suggests SSRF
            baseline_length = len(baseline_response.text)
            test_length = len(test_response.text)
            
            if abs(test_length - baseline_length) > 100:
                return True
        
        return False
    
    #New method for getting detected indicators (NEW ADDITION)
    def _get_detected_indicators(self, response_content):
        """Get list of detected SSRF indicators"""
        detected = []
        response_lower = response_content.lower()
        
        for indicator in self.success_indicators:
            if indicator.lower() in response_lower:
                detected.append(indicator)
        
        return detected if detected else ["Response change detected"]
