"""Command injection detector for SPECTR scanner"""

import time
from payloads.command_injection_payloads import CommandInjectionPayloads

class CommandInjectionDetector:
    """Detects command injection vulnerabilities"""

    def __init__(self):
        self.name = "Command Injection"
        self.payloads = CommandInjectionPayloads()
        self.success_indicators = CommandInjectionPayloads.get_success_indicators()

    def detect(self, target_url, method, parameters, headers, http_client, verbose=False):
        """Detect command injection vulnerabilities with comprehensive testing"""
        vulnerabilities = []

        if not parameters:
            if verbose:
                print(f"    [Command Injection] No parameters to test")
            return vulnerabilities

        # Get baseline response and response time
        try:
            baseline_response = http_client.get_baseline_response(target_url, method, parameters, headers)
            baseline_time = baseline_response.elapsed.total_seconds()
        except Exception as e:
            if verbose:
                print(f"    [Command Injection] Error getting baseline: {str(e)}")
            return vulnerabilities

        for param_name, param_value in parameters.items():
            if verbose:
                print(f"    [Command Injection] Testing parameter: {param_name}")

            #Basic command injection payloads
            for payload in CommandInjectionPayloads.BASIC_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = str(param_value) + payload
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    response_content = response.text
                    detected = self._get_detected_indicators(response_content)
                    if detected:
                        vulnerabilities.append(self._create_vuln("basic", param_name, payload, response, detected))
                        if verbose:
                            print(f"      [Command Injection] Found vulnerability! Output: {', '.join(detected)}")
                except Exception as e:
                    if verbose:
                        print(f"      [Command Injection] Error testing payload: {str(e)}")
                    continue

            # Time-based payloads
            for payload in CommandInjectionPayloads.TIME_BASED_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = str(param_value) + payload
                try:
                    start_time = time.time()
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    response_time = time.time() - start_time
                    if response_time > baseline_time + 3:  # adjust threshold
                        # Confirm delay
                        vulnerabilities.append(self._create_vuln("time", param_name, payload, response, [], delay=response_time))
                        if verbose:
                            print(f"      [Command Injection] Found time-based injection! Delay: {response_time - baseline_time:.2f}s")
                except Exception as e:
                    if verbose:
                        print(f"      [Command Injection] Error testing time-based payload: {str(e)}")
                    continue

            # Encoded payloads
            for payload in CommandInjectionPayloads.BYPASS_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = str(param_value) + payload
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    detected = self._get_detected_indicators(response.text)
                    if detected:
                        vulnerabilities.append(self._create_vuln("encoded", param_name, payload, response, detected))
                        if verbose:
                            print(f"      [Command Injection] Found encoded injection! Output: {', '.join(detected)}")
                except Exception as e:
                    if verbose:
                        print(f"      [Command Injection] Error testing encoded payload: {str(e)}")
                    continue

            # Windows payloads
            for payload in CommandInjectionPayloads.WINDOWS_PAYLOADS:
                test_params = parameters.copy()
                test_params[param_name] = str(param_value) + payload
                try:
                    if method.upper() == 'GET':
                        response = http_client.make_request(target_url, method, params=test_params, headers=headers)
                    else:
                        response = http_client.make_request(target_url, method, data=test_params, headers=headers)
                    detected = self._get_detected_indicators(response.text)
                    if detected:
                        vulnerabilities.append(self._create_vuln("windows", param_name, payload, response, detected))
                        if verbose:
                            print(f"      [Command Injection] Found Windows payload! Output: {', '.join(detected)}")
                except Exception as e:
                    if verbose:
                        print(f"      [Command Injection] Error testing Windows payload: {str(e)}")
                    continue

        return vulnerabilities

    def _create_vuln(self, vuln_type, param, payload, response, indicators, delay=None):
        """Create a vulnerability dict with optional timing info"""
        vuln = {
            'vulnerability_type': 'command_injection',
            'parameter': param,
            'payload': payload,
            'method': 'GET' if 'params' in response.request_kwargs else 'POST',
            'evidence': f"Command execution detected: {', '.join(indicators)}" if indicators else None,
            'response_snippet': response.text[:500]
        }
        if delay:
            vuln['delay_seconds'] = delay
        return vuln

    def _get_detected_indicators(self, response_content):
        indicators = self.success_indicators
        detected = []
        response_lower = response_content.lower()

        # Check for indicators such as 'id', 'whoami', 'net user', 'systeminfo', etc.
        for indicator in indicators:
            if indicator.lower() in response_lower:
                detected.append(indicator)
        return detected
