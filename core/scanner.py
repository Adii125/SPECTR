"""Main scanner class for SPECTR vulnerability scanner"""

import json
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from core.http_client import HttpClient
from detectors.sqli_detector import SqliDetector
from detectors.xss_detector import XssDetector
from detectors.idor_detector import IdorDetector
from detectors.path_traversal_detector import PathTraversalDetector
from detectors.xxe_detector import XxeDetector
from detectors.command_injection_detector import CommandInjectionDetector
from detectors.ssrf_detector import SsrfDetector
from utils.colors import Colors
from utils.input_validator import InputValidator
from utils.report_generator import ReportGenerator

class SpectrScanner:
    """Main scanner class that orchestrates vulnerability detection"""

    def __init__(self):
        self.target_url = ""
        self.http_method = "GET"
        self.parameters = {}
        self.headers = {}
        self.verbose = False
        self.results = []
        self.http_client = HttpClient()

        # Initialize ALL detectors
        self.detectors = [
            SqliDetector(),
            XssDetector(),
            IdorDetector(),
            PathTraversalDetector(),
            XxeDetector(),
            CommandInjectionDetector(),
            SsrfDetector()
        ]

    def run(self):
        """Main scanning workflow"""
        print(f"{Colors.CYAN}🔧 Starting SPECTR comprehensive scan...{Colors.RESET}\n")

        # Get user inputs
        self._get_user_inputs()

        # Validate inputs
        if not self._validate_inputs():
            return

        # Start scanning
        self._perform_scan()

        # Display results
        self._display_results()

        # Generate report
        self._generate_report()

    def _get_user_inputs(self):
        """Get scanning parameters from user"""
        print(f"{Colors.YELLOW}📋 Please provide scanning parameters:{Colors.RESET}\n")

        # Get target URL
        while True:
            self.target_url = input(f"{Colors.BLUE}🔗 Enter target URL: {Colors.RESET}").strip()
            if self.target_url:
                if not self.target_url.startswith(('http://', 'https://')):
                    self.target_url = 'http://' + self.target_url
                break
            print(f"{Colors.RED}❌ URL is required!{Colors.RESET}")

        # Get HTTP method
        while True:
            method = input(f"{Colors.BLUE}📡 HTTP method (GET/POST) [GET]: {Colors.RESET}").strip().upper()
            if method in ['GET', 'POST', '']:
                self.http_method = method if method else 'GET'
                break
            print(f"{Colors.RED}❌ Only GET and POST methods are supported!{Colors.RESET}")

        # Get parameters
        params_input = input(f"{Colors.BLUE}📤 Parameters (e.g., id=1&user=admin): {Colors.RESET}").strip()
        if params_input:
            self.parameters = self._parse_parameters(params_input)

        # Get headers
        headers_input = input(f"{Colors.BLUE}🧾 Headers (key:value,key:value) [optional]: {Colors.RESET}").strip()
        if headers_input:
            self.headers = self._parse_headers(headers_input)

        # Get verbose mode
        verbose_input = input(f"{Colors.BLUE}🔍 Verbose mode? (y/n) [n]: {Colors.RESET}").strip().lower()
        self.verbose = verbose_input == 'y'

        print()  # Add spacing

    def _parse_parameters(self, params_str):
        """Parse parameter string into dictionary"""
        params = {}
        try:
            # Parse URL-encoded parameters
            parsed_params = parse_qs(params_str, keep_blank_values=True)
            for key, value_list in parsed_params.items():
                params[key] = value_list[0] if value_list else ''
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️ Warning: Could not parse parameters: {e}{Colors.RESET}")
        return params

    def _parse_headers(self, headers_str):
        """Parse headers string into dictionary"""
        headers = {}
        try:
            for header_pair in headers_str.split(','):
                if ':' in header_pair:
                    key, value = header_pair.split(':', 1)
                    headers[key.strip()] = value.strip()
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️ Warning: Could not parse headers: {e}{Colors.RESET}")
        return headers

    def _validate_inputs(self):
        """Validate user inputs"""
        validator = InputValidator()

        if not validator.is_valid_url(self.target_url):
            print(f"{Colors.RED}❌ Invalid URL format!{Colors.RESET}")
            return False

        return True

    def _perform_scan(self):
        """Perform comprehensive vulnerability scanning"""
        print(f"{Colors.CYAN}⏳ Scanning {self.target_url}...{Colors.RESET}")
        print(f"{Colors.CYAN}🎯 Method: {self.http_method}{Colors.RESET}")
        if self.parameters:
            print(f"{Colors.CYAN}📝 Parameters: {list(self.parameters.keys())}{Colors.RESET}")
        print(f"{Colors.CYAN}🔍 Detectors: {len(self.detectors)} vulnerability types{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")

        start_time = time.time()

        # Run each detector
        for detector in self.detectors:
            if self.verbose:
                print(f"{Colors.YELLOW}🔍 Running {detector.name} detector...{Colors.RESET}")

            try:
                vulnerabilities = detector.detect(
                    self.target_url,
                    self.http_method,
                    self.parameters,
                    self.headers,
                    self.http_client,
                    self.verbose
                )

                if vulnerabilities:
                    self.results.extend(vulnerabilities)
                    if self.verbose:
                        print(f"{Colors.GREEN}✅ Found {len(vulnerabilities)} {detector.name} vulnerabilities{Colors.RESET}")
                elif self.verbose:
                    print(f"{Colors.BLUE}ℹ️ No {detector.name} vulnerabilities found{Colors.RESET}")

                if self.verbose:
                    print()  # Add spacing between detectors

            except Exception as e:
                error_msg = f"Error in {detector.name} detector: {str(e)}"
                print(f"{Colors.RED}❌ {error_msg}{Colors.RESET}")
                if self.verbose:
                    import traceback
                    print(f"{Colors.RED}{traceback.format_exc()}{Colors.RESET}")

        scan_time = time.time() - start_time
        print(f"\n{Colors.CYAN}⏱️ Comprehensive scan completed in {scan_time:.2f} seconds{Colors.RESET}\n")

    def _display_results(self):
        """Display comprehensive scan results"""
        if not self.results:
            print(f"{Colors.GREEN}✅ No vulnerabilities found across all {len(self.detectors)} vulnerability types!{Colors.RESET}\n")
            return

        print(f"{Colors.RED}🚨 VULNERABILITIES DETECTED:{Colors.RESET}\n")

        # Group results by vulnerability type
        grouped_results = {}
        for result in self.results:
            vuln_type = result['vulnerability_type']
            if vuln_type not in grouped_results:
                grouped_results[vuln_type] = []
            grouped_results[vuln_type].append(result)

        # Display grouped results with severity ranking
        severity_order = ['sqli', 'command_injection', 'xxe', 'path_traversal', 'xss', 'ssrf', 'idor']

        for vuln_type in severity_order:
            if vuln_type in grouped_results:
                vulns = grouped_results[vuln_type]
                severity = self._get_severity(vuln_type)
                print(f"{Colors.RED}📍 {vuln_type.upper()} - {severity} ({len(vulns)} found):{Colors.RESET}")

                for i, vuln in enumerate(vulns, 1):
                    param = vuln.get('parameter', 'N/A')
                    payload = vuln.get('payload', 'N/A')
                    evidence = vuln.get('evidence', 'No evidence')

                    print(f"  {Colors.YELLOW}{i}. Parameter:{Colors.RESET} {param}")
                    print(f"     {Colors.YELLOW}Payload:{Colors.RESET} {payload}")
                    print(f"     {Colors.YELLOW}Evidence:{Colors.RESET} {evidence[:80]}...")
                    print()

        print(f"{Colors.RED}📊 Total vulnerabilities found: {len(self.results)} across {len(grouped_results)} vulnerability types{Colors.RESET}\n")

        # Display impact summary
        self._display_impact_summary(grouped_results)

    def _get_severity(self, vuln_type):
        """Get severity level for vulnerability type"""
        severity_map = {
            'sqli': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'xxe': 'HIGH',
            'path_traversal': 'HIGH', 
            'xss': 'MEDIUM',
            'ssrf': 'MEDIUM',
            'idor': 'MEDIUM'
        }
        return severity_map.get(vuln_type, 'UNKNOWN')

    def _display_impact_summary(self, grouped_results):
        """Display impact summary of findings"""
        print(f"{Colors.YELLOW}💥 IMPACT SUMMARY:{Colors.RESET}")

        critical_count = len(grouped_results.get('sqli', [])) + len(grouped_results.get('command_injection', []))
        high_count = len(grouped_results.get('xxe', [])) + len(grouped_results.get('path_traversal', []))
        medium_count = len(grouped_results.get('xss', [])) + len(grouped_results.get('ssrf', [])) + len(grouped_results.get('idor', []))

        if critical_count > 0:
            print(f"🔴 CRITICAL: {critical_count} vulnerabilities - Immediate action required!")
        if high_count > 0:
            print(f"🟠 HIGH: {high_count} vulnerabilities - Patch as soon as possible")
        if medium_count > 0:
            print(f"🟡 MEDIUM: {medium_count} vulnerabilities - Address in next security update")
        print()

    def _generate_report(self):
        """Generate and save comprehensive JSON report"""
        report_generator = ReportGenerator()

        # Calculate vulnerability statistics
        vuln_stats = {}
        for result in self.results:
            vuln_type = result['vulnerability_type']
            vuln_stats[vuln_type] = vuln_stats.get(vuln_type, 0) + 1

        report_data = {
            'scan_info': {
                'target_url': self.target_url,
                'method': self.http_method,
                'parameters': self.parameters,
                'headers': self.headers,
                'scan_time': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.results),
                'vulnerability_types_tested': len(self.detectors),
                'vulnerability_statistics': vuln_stats,
                'detectors_used': [detector.name for detector in self.detectors]
            },
            'vulnerabilities': self.results,
            'summary': {
                'critical_vulnerabilities': len([v for v in self.results if v['vulnerability_type'] in ['sqli', 'command_injection']]),
                'high_vulnerabilities': len([v for v in self.results if v['vulnerability_type'] in ['xxe', 'path_traversal']]),
                'medium_vulnerabilities': len([v for v in self.results if v['vulnerability_type'] in ['xss', 'ssrf', 'idor']])
            }
        }

        filename = report_generator.generate_json_report(report_data)
        if filename:
            print(f"{Colors.GREEN}💾 Comprehensive report saved to: {filename}{Colors.RESET}\n")
