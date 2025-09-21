"""Input validation utilities for SPECTR scanner"""

import re
from urllib.parse import urlparse

class InputValidator:
    """Validates user inputs for security and correctness"""

    @staticmethod
    def is_valid_url(url):
        """Validate if URL format is correct"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def sanitize_parameter_name(param_name):
        """Sanitize parameter name for safe processing"""
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[^a-zA-Z0-9_\-\[\]]', '', param_name)
        return sanitized[:50]  # Limit length
