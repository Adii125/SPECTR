"""XML External Entity (XXE) detector for SPECTR scanner"""

from payloads.xxe_payloads import XxePayloads

class XxeDetector:
    """Detects XXE vulnerabilities"""
    
    def __init__(self):
        self.name = "XXE"
        self.payloads = XxePayloads()
        self.success_indicators = XxePayloads.get_success_indicators()
    
    def detect(self, target_url, method, parameters, headers, http_client, verbose=False):
        """Detect XXE vulnerabilities with comprehensive testing"""
        vulnerabilities = []
        
        if not parameters:
            if verbose:
                print(f"    [XXE] No parameters to test")
            return vulnerabilities
        
        #Test EVERY parameter for XXE
        for param_name, param_value in parameters.items():
            if verbose:
                print(f"    [XXE] Testing parameter: {param_name}")
            
            #Test parameter-based XXE
            for payload in XxePayloads.PARAMETER_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = payload  # Inject XXE into parameter
                
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    
                    response_content = response.text
                    
                    # Check for XXE success indicators
                    detected_indicators = self._get_detected_indicators(response_content)
                    if detected_indicators:
                        vulnerability = {
                            'vulnerability_type': 'xxe',
                            'parameter': param_name,
                            'payload': payload[:200] + "..." if len(payload) > 200 else payload,
                            'method': method,
                            'evidence': f"XXE successful - detected: {', '.join(detected_indicators)}",
                            'response_snippet': response_content[:500]
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"      [XXE] Found XXE vulnerability! Indicators: {', '.join(detected_indicators)}")
                
                except Exception as e:
                    if verbose:
                        print(f"      [XXE] Error testing parameter payload: {str(e)}")
                    continue
            
            #Also test with XML content-type for completeness
            for payload in XxePayloads.BASIC_PAYLOADS:
                test_headers = headers.copy()
                test_headers['Content-Type'] = 'application/xml'
                
                try:
                    if method.upper() == 'POST':
                        response = http_client.make_request(target_url, method, data=payload, headers=test_headers)
                    else:
                        # Try as parameter even with XML payload
                        test_params = parameters.copy()
                        test_params[param_name] = payload
                        response = http_client.make_request(target_url, method, params=test_params, headers=test_headers)
                    
                    detected_indicators = self._get_detected_indicators(response.text)
                    if detected_indicators:
                        vulnerability = {
                            'vulnerability_type': 'xxe',
                            'parameter': param_name,
                            'payload': "XML payload with external entity",
                            'method': method,
                            'evidence': f"XXE via XML content-type: {', '.join(detected_indicators)}",
                            'response_snippet': response.text[:500]
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"      [XXE] Found XML-based XXE! Indicators: {', '.join(detected_indicators)}")
                
                except Exception as e:
                    if verbose:
                        print(f"      [XXE] Error testing XML payload: {str(e)}")
                    continue
        
        return vulnerabilities
    
    #Enhanced detection method
    def _get_detected_indicators(self, response_content):
        """Get list of detected XXE indicators"""
        detected = []
        response_lower = response_content.lower()
        
        for indicator in self.success_indicators:
            if indicator.lower() in response_lower:
                detected.append(indicator)
        
        return detected
