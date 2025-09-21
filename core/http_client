"""HTTP client for making requests during vulnerability scanning"""

import requests
import time
import random
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class HttpClient:
    """HTTP client for making requests with proper error handling"""

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False  # Allow self-signed certificates
        self.session.timeout = 15

        # Set common headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })

        self.delay_range = (0.3, 0.8)  # Delays between requests

    def make_request(self, url, method='GET', params=None, data=None, headers=None, allow_redirects=True):
        """Make HTTP request with comprehensive error handling"""
        try:
            # Add custom headers if provided
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)

            # Add random delay to avoid being blocked
            time.sleep(random.uniform(*self.delay_range))

            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    params=params,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    timeout=self.session.timeout
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    params=params,
                    data=data,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    timeout=self.session.timeout
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            return response

        except requests.exceptions.Timeout:
            raise Exception("Request timeout - server may be slow or unresponsive")
        except requests.exceptions.ConnectionError as e:
            raise Exception(f"Connection error - server may be down or unreachable: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request error: {str(e)}")
        except Exception as e:
            raise Exception(f"Unexpected error: {str(e)}")

    def get_baseline_response(self, url, method, params, headers):
        """Get baseline response for comparison"""
        try:
            if method.upper() == 'GET':
                return self.make_request(url, method, params=params, headers=headers)
            else:
                return self.make_request(url, method, data=params, headers=headers)
        except Exception as e:
            raise Exception(f"Failed to get baseline response: {str(e)}")
