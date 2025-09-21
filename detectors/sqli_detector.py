"""SQL Injection detector for SPECTR scanner"""

import time
from payloads.sqli_payloads import SqliPayloads

class SqliDetector:
    """Detects SQL injection vulnerabilities - Error-based, Time-based, and Boolean-based"""
    
    def __init__(self):
        self.name = "SQLi"
        self.payloads = SqliPayloads()
        self.error_indicators = SqliPayloads.get_error_indicators()
    
    def detect(self, target_url, method, parameters, headers, http_client, verbose=False):
        """Detect SQL injection vulnerabilities with comprehensive testing"""
        vulnerabilities = []
        
        if not parameters:
            if verbose:
                print(f"    [SQLi] No parameters to test")
            return vulnerabilities
        
        # Get baseline response for comparison
        try:
            baseline_response = http_client.get_baseline_response(target_url, method, parameters, headers)
            baseline_content = baseline_response.text.lower()
            baseline_time = baseline_response.elapsed.total_seconds()
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
            
            if verbose:
                print(f"    [SQLi] Baseline established: {baseline_time:.2f}s, {baseline_length} chars, status {baseline_status}")
                
        except Exception as e:
            if verbose:
                print(f"    [SQLi] Error getting baseline: {str(e)}")
            return vulnerabilities
        
        # Test each parameter for all types of SQLi
        for param_name, param_value in parameters.items():
            if verbose:
                print(f"    [SQLi] Testing parameter: {param_name}")
            
            # 1. ERROR-BASED SQL INJECTION TESTING
            if verbose:
                print(f"      [SQLi] Testing error-based SQLi...")
            
            for payload in SqliPayloads.ERROR_BASED:
                test_params = parameters.copy()
                test_params[param_name] = str(param_value) + payload
                
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    
                    response_content = response.text.lower()
                    
                    # Check for SQL error messages
                    for error_indicator in self.error_indicators:
                        if error_indicator in response_content:
                            vulnerability = {
                                'vulnerability_type': 'sqli',
                                'sqli_type': 'error_based',
                                'parameter': param_name,
                                'payload': payload,
                                'method': method,
                                'evidence': f"SQL error detected: {error_indicator}",
                                'response_snippet': response.text[:300],
                                'severity': 'CRITICAL'
                            }
                            vulnerabilities.append(vulnerability)
                            if verbose:
                                print(f"        [SQLi] ✅ Error-based SQLi found: {error_indicator}")
                            break
                    
                    # Check for status code differences
                    if response.status_code != baseline_status and response.status_code in [500, 400]:
                        vulnerability = {
                            'vulnerability_type': 'sqli',
                            'sqli_type': 'error_based',
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f"HTTP status changed from {baseline_status} to {response.status_code}",
                            'response_snippet': response.text[:300],
                            'severity': 'CRITICAL'
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"        [SQLi] ✅ Error-based SQLi found: Status code change")
                
                except Exception as e:
                    if verbose:
                        print(f"        [SQLi] Error testing error-based payload {payload}: {str(e)}")
                    continue
            
            # 2. TIME-BASED SQL INJECTION TESTING
            if verbose:
                print(f"      [SQLi] Testing time-based SQLi...")
            
            for payload in SqliPayloads.TIME_BASED:
                test_params = parameters.copy()
                test_params[param_name] = str(param_value) + payload
                
                try:
                    start_time = time.time()
                    
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    
                    response_time = time.time() - start_time
                    
                    # Check if response took significantly longer (indicating successful injection)
                    delay_threshold = 3.0  # 3 seconds
                    if response_time > baseline_time + delay_threshold:
                        # Verify with a second test to avoid false positives
                        if verbose:
                            print(f"        [SQLi] Potential time-based SQLi detected, verifying...")
                        
                        # Second verification test
                        start_time2 = time.time()
                        if method.upper() == 'GET':
                            response2 = http_client.make_request(target_url, method, params=test_params, headers=headers)
                        else:
                            response2 = http_client.make_request(target_url, method, data=test_params, headers=headers)
                        response_time2 = time.time() - start_time2
                        
                        # If both tests show delay, confirm time-based SQLi
                        if response_time2 > baseline_time + delay_threshold:
                            vulnerability = {
                                'vulnerability_type': 'sqli',
                                'sqli_type': 'time_based',
                                'parameter': param_name,
                                'payload': payload,
                                'method': method,
                                'evidence': f"Time-based SQLi confirmed - Delay: {response_time:.2f}s, Verify: {response_time2:.2f}s",
                                'response_snippet': response.text[:300],
                                'severity': 'CRITICAL'
                            }
                            vulnerabilities.append(vulnerability)
                            if verbose:
                                print(f"        [SQLi] ✅ Time-based SQLi confirmed: {response_time:.2f}s delay")
                
                except Exception as e:
                    if verbose:
                        print(f"        [SQLi] Error testing time-based payload: {str(e)}")
                    continue
            
            # 3. BOOLEAN-BASED SQL INJECTION TESTING
            if verbose:
                print(f"      [SQLi] Testing boolean-based SQLi...")
            
            # Test boolean-based SQLi with true/false pairs
            for true_payload, false_payload in SqliPayloads.BOOLEAN_BASED:
                try:
                    # Test TRUE condition
                    test_params_true = parameters.copy()
                    test_params_true[param_name] = str(param_value) + true_payload
                    
                    if method.upper() == 'GET':
                        response_true = http_client.make_request(target_url, method, params=test_params_true, headers=headers)
                    else:
                        response_true = http_client.make_request(target_url, method, data=test_params_true, headers=headers)
                    
                    # Test FALSE condition
                    test_params_false = parameters.copy()
                    test_params_false[param_name] = str(param_value) + false_payload
                    
                    if method.upper() == 'GET':
                        response_false = http_client.make_request(target_url, method, params=test_params_false, headers=headers)
                    else:
                        response_false = http_client.make_request(target_url, method, data=test_params_false, headers=headers)
                    
                    # Analyze response differences
                    true_length = len(response_true.text)
                    false_length = len(response_false.text)
                    length_diff = abs(true_length - false_length)
                    
                    # Check for significant response differences
                    significant_diff_threshold = max(50, baseline_length * 0.05)  # 5% or 50 chars minimum
                    
                    if length_diff > significant_diff_threshold:
                        # Additional checks for boolean-based SQLi
                        content_similarity = self._calculate_similarity(response_true.text, response_false.text)
                        
                        if content_similarity < 0.95:  # Less than 95% similar
                            vulnerability = {
                                'vulnerability_type': 'sqli',
                                'sqli_type': 'boolean_based',
                                'parameter': param_name,
                                'payload': f"TRUE: {true_payload} | FALSE: {false_payload}",
                                'method': method,
                                'evidence': f"Boolean-based SQLi - Length diff: {length_diff} chars, Similarity: {content_similarity:.2%}",
                                'response_snippet': f"TRUE: {response_true.text[:150]}... | FALSE: {response_false.text[:150]}...",
                                'severity': 'CRITICAL'
                            }
                            vulnerabilities.append(vulnerability)
                            if verbose:
                                print(f"        [SQLi] ✅ Boolean-based SQLi found: {length_diff} chars difference")
                    
                    # Check for different HTTP status codes
                    if response_true.status_code != response_false.status_code:
                        vulnerability = {
                            'vulnerability_type': 'sqli',
                            'sqli_type': 'boolean_based',
                            'parameter': param_name,
                            'payload': f"TRUE: {true_payload} | FALSE: {false_payload}",
                            'method': method,
                            'evidence': f"Boolean-based SQLi - Status code diff: TRUE={response_true.status_code}, FALSE={response_false.status_code}",
                            'response_snippet': f"TRUE: {response_true.text[:150]}... | FALSE: {response_false.text[:150]}...",
                            'severity': 'CRITICAL'
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"        [SQLi] ✅ Boolean-based SQLi found: Status code difference")
                
                except Exception as e:
                    if verbose:
                        print(f"        [SQLi] Error testing boolean-based payload: {str(e)}")
                    continue
        
        if verbose and vulnerabilities:
            print(f"    [SQLi] Total SQLi vulnerabilities found: {len(vulnerabilities)}")
            
        return vulnerabilities
    
    def _calculate_similarity(self, text1, text2):
        """Calculate similarity between two text responses (simple approach)"""
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        # Simple similarity based on common characters
        set1 = set(text1.lower())
        set2 = set(text2.lower())
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
