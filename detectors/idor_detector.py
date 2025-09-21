"""Insecure Direct Object Reference (IDOR) detector for SPECTR scanner"""

from payloads.idor_payloads import IdorPayloads

class IdorDetector:
    """Detects IDOR vulnerabilities"""

    def __init__(self):
        self.name = "IDOR"
        self.payloads = IdorPayloads()
        self.sensitive_indicators = IdorPayloads.get_sensitive_indicators()

    def detect(self, target_url, method, parameters, headers, http_client, verbose=False):
        """Detect IDOR vulnerabilities"""
        vulnerabilities = []

        if not parameters:
            if verbose:
                print(f"    [IDOR] No parameters to test")
            return vulnerabilities

        # Get baseline response
        try:
            baseline_response = http_client.get_baseline_response(target_url, method, parameters, headers)
            baseline_content = baseline_response.text
            baseline_status = baseline_response.status_code
        except Exception as e:
            if verbose:
                print(f"    [IDOR] Error getting baseline: {str(e)}")
            return vulnerabilities

        # Test each parameter that looks like an ID
        for param_name, param_value in parameters.items():
            if not self._is_potential_id_parameter(param_name, param_value):
                continue

            if verbose:
                print(f"    [IDOR] Testing ID parameter: {param_name}")

            # Test different ID values
            test_payloads = self._get_appropriate_payloads(param_value)

            for payload in test_payloads:  # Limit for efficiency
                test_params = parameters.copy()
                test_params[param_name] = payload

                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)

                    # Check for successful IDOR
                    if self._is_idor_successful(baseline_response, response):
                        vulnerability = {
                            'vulnerability_type': 'idor',
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f"IDOR detected - accessed different object with ID: {payload}",
                            'response_snippet': response.text[:300]
                        }
                        vulnerabilities.append(vulnerability)
                        if verbose:
                            print(f"      [IDOR] Found IDOR with ID: {payload}")

                except Exception as e:
                    if verbose:
                        print(f"      [IDOR] Error testing payload {payload}: {str(e)}")
                    continue

        return vulnerabilities

    def _is_potential_id_parameter(self, param_name, param_value):
        """Check if parameter looks like an ID"""
        id_indicators = ['id', 'uid', 'user', 'account', 'profile']
        param_lower = param_name.lower()

        for indicator in id_indicators:
            if indicator in param_lower:
                return True

        # Check if value looks like a numeric ID
        try:
            if str(param_value).isdigit():
                return True
        except:
            pass

        return False

    def _get_appropriate_payloads(self, original_value):
        """Get appropriate test payloads based on original value type"""
        payloads = []

        try:
            if str(original_value).isdigit():
                original_num = int(original_value)
                payloads.extend([
                    str(original_num + 1),
                    str(original_num - 1),
                    "1", "2", "0", "999"
                ])
            else:
                payloads.extend(IdorPayloads.STRING_IDS)
        except:
            payloads.extend(IdorPayloads.NUMERIC_IDS)

        # Remove original value
        payloads = [p for p in payloads if p != str(original_value)]
        return payloads[:8]

    def _is_idor_successful(self, baseline_response, test_response):
        """Check if IDOR was successful"""
        # Check if we got a successful response
        if test_response.status_code != 200:
            return False

        # Check if response is different from baseline
        baseline_length = len(baseline_response.text)
        test_length = len(test_response.text)

        # If response is significantly different, might be IDOR
        if abs(test_length - baseline_length) > 50:
            return True

        return False
