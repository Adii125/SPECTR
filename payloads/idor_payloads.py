"""Insecure Direct Object Reference (IDOR) payloads for SPECTR scanner"""

class IdorPayloads:
    """Collection of IDOR test values"""

    # Numeric ID variations
    NUMERIC_IDS = [
        "1", "2", "3", "0", "-1", "999", "1000", "9999", "10000",
        "100", "1234", "5678"
    ]

    # String ID variations
    STRING_IDS = [
        "admin", "administrator", "root", "test", "guest", "user",
        "demo", "default", "system", "operator", "manager",
        "superuser", "admin1", "admin2", "administrator1", "administrator2",
        "testuser", "demo1", "demo2", "guest1", "guest2", "systemadmin", "sysadmin",
        "operator1", "operator2", "manager1", "manager2", "rootuser", "root1", "root2"
    ]

    @classmethod
    def get_all_payloads(cls):
        """Get all IDOR test payloads"""
        return cls.NUMERIC_IDS + cls.STRING_IDS

    @classmethod
    def get_sensitive_indicators(cls):
        """Get indicators of sensitive information exposure"""
        return [
            "password", "passwd", "secret", "key", "token",
            "email", "@", "phone", "account", "balance",
            "admin", "root", "private", "confidential"
        ]
