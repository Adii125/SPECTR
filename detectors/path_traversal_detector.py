"""Path traversal detector for SPECTR scanner"""


from payloads.path_traversal_payloads import PathTraversalPayloads

class PathTraversalDetector:
    """Detects path traversal vulnerabilities"""
    
    def __init__(self):
        self.name = "Path Traversal"
        self.payloads = PathTraversalPayloads()
        self.success_indicators = PathTraversalPayloads.get_success_indicators()
    
    def detect(self, target_url, method, parameters, headers, http_client, verbose=False):
        """Detect path traversal vulnerabilities with comprehensive testing"""
        vulnerabilities = []
        
        if not parameters:
            if verbose:
                print(f"    [Path Traversal] No parameters to test")
            return vulnerabilities
        
        # Test ALL parameters
        for param_name, param_value in parameters.items():
            if verbose:
                print(f"    [Path Traversal] Testing parameter: {param_name}")
            
            #Test MORE payloads for better coverage
            for payload in PathTraversalPayloads.BASIC_PAYLOADS:  # Increased from 4 to 10
                test_params = parameters.copy()
                test_params[param_name] = payload  # Replace value completely
                
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    
                    response_content = response.text
                    
                    #ENHANCED detection with more indicators
                    detected_indicators = self._get_detected_indicators(response_content)
                    if detected_indicators:
                        vulnerability = {
                            'vulnerability_type': 'path_traversal',
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f"File content detected: {', '.join(detected_indicators)}",
                            'response_snippet': response_content[:500]  # More content for analysis
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"      [Path Traversal] Found vulnerability! Indicators: {', '.join(detected_indicators)}")
                
                except Exception as e:
                    if verbose:
                        print(f"      [Path Traversal] Error testing payload: {str(e)}")
                    continue
            
            #Also test encoded payloads
            for payload in PathTraversalPayloads.ENCODED_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = payload
                
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    
                    detected_indicators = self._get_detected_indicators(response.text)
                    if detected_indicators:
                        vulnerability = {
                            'vulnerability_type': 'path_traversal',
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f"File content detected (encoded): {', '.join(detected_indicators)}",
                            'response_snippet': response.text[:500]
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"      [Path Traversal] Found encoded traversal! Indicators: {', '.join(detected_indicators)}")
                
                except Exception as e:
                    if verbose:
                        print(f"      [Path Traversal] Error testing encoded payload: {str(e)}")
                    continue
        
        return vulnerabilities
    
    #sEnhanced detection method
    def _get_detected_indicators(self, response_content):
        """Get list of detected file content indicators"""
        detected = []
        response_lower = response_content.lower()
        
        for indicator in self.success_indicators:
            if indicator.lower() in response_lower:
                detected.append(indicator)
        
        return detected
