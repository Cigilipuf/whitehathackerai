"""WhiteHatHacker AI — Comprehensive Remediation Guidance Module.

Provides vulnerability-type-specific, actionable remediation advice
with code examples, OWASP references, and technology-specific guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from loguru import logger


@dataclass
class RemediationAdvice:
    """Structured remediation advice for a vulnerability."""

    summary: str = ""
    detail: str = ""
    code_examples: list[CodeExample] = field(default_factory=list)
    owasp_refs: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    priority: str = "medium"  # immediate, high, medium, low
    estimated_effort: str = ""  # e.g. "1-2 hours", "1 day"


@dataclass
class CodeExample:
    """A code example showing how to remediate."""

    language: str  # python, javascript, java, php, nginx, apache, generic
    title: str
    vulnerable: str  # vulnerable code
    fixed: str  # fixed code


# ---------------------------------------------------------------------------
# Remediation Database
# ---------------------------------------------------------------------------

_REMEDIATIONS: dict[str, dict[str, Any]] = {
    # ── INJECTION ──────────────────────────────────────────────────────────
    "sql_injection": {
        "summary": (
            "Use parameterized queries (prepared statements) for ALL database "
            "interactions. Never concatenate user input into SQL strings."
        ),
        "detail": (
            "SQL injection occurs when untrusted data is sent to a database "
            "interpreter as part of a command. The most effective defense is "
            "parameterized queries which separate SQL logic from data. "
            "Additionally:\n"
            "- Apply least-privilege database permissions\n"
            "- Use stored procedures where appropriate\n"
            "- Validate input types (e.g., ensure numeric IDs are integers)\n"
            "- Deploy a WAF as defense-in-depth\n"
            "- Use ORM frameworks that auto-parameterize"
        ),
        "code_examples": [
            {
                "language": "python",
                "title": "Python (psycopg2 / SQLAlchemy)",
                "vulnerable": (
                    '# VULNERABLE - string concatenation\n'
                    'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
                    'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'
                ),
                "fixed": (
                    '# FIXED - parameterized query\n'
                    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n\n'
                    '# FIXED - SQLAlchemy ORM\n'
                    'user = session.query(User).filter(User.id == user_id).first()'
                ),
            },
            {
                "language": "javascript",
                "title": "Node.js (mysql2 / knex)",
                "vulnerable": (
                    '// VULNERABLE\n'
                    'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);'
                ),
                "fixed": (
                    '// FIXED - parameterized query\n'
                    'db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);\n\n'
                    '// FIXED - Knex query builder\n'
                    'knex("users").where("id", req.params.id).first();'
                ),
            },
            {
                "language": "java",
                "title": "Java (PreparedStatement)",
                "vulnerable": (
                    '// VULNERABLE\n'
                    'Statement st = conn.createStatement();\n'
                    'st.executeQuery("SELECT * FROM users WHERE id = " + userId);'
                ),
                "fixed": (
                    '// FIXED\n'
                    'PreparedStatement ps = conn.prepareStatement(\n'
                    '    "SELECT * FROM users WHERE id = ?");\n'
                    'ps.setInt(1, userId);\n'
                    'ResultSet rs = ps.executeQuery();'
                ),
            },
            {
                "language": "php",
                "title": "PHP (PDO)",
                "vulnerable": (
                    '// VULNERABLE\n'
                    '$result = $pdo->query("SELECT * FROM users WHERE id = " . $_GET["id"]);'
                ),
                "fixed": (
                    '// FIXED - PDO prepared statement\n'
                    '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n'
                    '$stmt->execute(["id" => $_GET["id"]]);'
                ),
            },
        ],
        "owasp_refs": ["OWASP A03:2021 — Injection", "OWASP SQL Injection Prevention Cheat Sheet"],
        "cwe_ids": ["CWE-89"],
        "priority": "immediate",
        "estimated_effort": "2-4 hours per endpoint",
    },
    "command_injection": {
        "summary": (
            "Never pass user input to system shell commands. Use language-native "
            "APIs instead of shell execution."
        ),
        "detail": (
            "Command injection allows attackers to execute arbitrary OS commands. "
            "The safest approach is to avoid shell commands entirely.\n"
            "- Use language APIs (e.g., Python's subprocess with shell=False)\n"
            "- If shell is necessary, use strict allowlists for input\n"
            "- Never use shell=True with user input\n"
            "- Apply AppArmor/SELinux profiles to limit command scope"
        ),
        "code_examples": [
            {
                "language": "python",
                "title": "Python subprocess",
                "vulnerable": (
                    '# VULNERABLE\n'
                    'os.system(f"ping -c 1 {host}")\n'
                    'subprocess.call(f"nslookup {domain}", shell=True)'
                ),
                "fixed": (
                    '# FIXED - no shell, arguments as list\n'
                    'subprocess.run(["ping", "-c", "1", host], shell=False,\n'
                    '               capture_output=True, timeout=10)\n\n'
                    '# FIXED - validate input against allowlist\n'
                    'import re\n'
                    'if not re.match(r"^[a-zA-Z0-9.-]+$", domain):\n'
                    '    raise ValueError("Invalid domain")'
                ),
            },
        ],
        "owasp_refs": ["OWASP A03:2021 — Injection", "OWASP OS Command Injection Defense Cheat Sheet"],
        "cwe_ids": ["CWE-78"],
        "priority": "immediate",
        "estimated_effort": "1-2 hours per endpoint",
    },
    "nosql_injection": {
        "summary": (
            "Sanitize and type-check all query inputs. Avoid passing raw user input "
            "to NoSQL query operators."
        ),
        "detail": (
            "NoSQL injection exploits query operator syntax in databases like MongoDB.\n"
            "- Always cast expected types (e.g., string, int)\n"
            "- Reject input containing $ operators ($gt, $ne, $regex etc.)\n"
            "- Use ODM libraries (Mongoose) with schema validation\n"
            "- Disable server-side JavaScript execution in MongoDB"
        ),
        "code_examples": [
            {
                "language": "javascript",
                "title": "MongoDB / Mongoose",
                "vulnerable": (
                    '// VULNERABLE - raw user input in query\n'
                    'db.users.find({ username: req.body.username,\n'
                    '                password: req.body.password });'
                ),
                "fixed": (
                    '// FIXED - type cast + sanitize\n'
                    'const username = String(req.body.username);\n'
                    'const password = String(req.body.password);\n'
                    'db.users.find({ username, password });\n\n'
                    '// FIXED - use express-mongo-sanitize middleware\n'
                    'const mongoSanitize = require("express-mongo-sanitize");\n'
                    'app.use(mongoSanitize());'
                ),
            },
        ],
        "owasp_refs": ["OWASP A03:2021 — Injection"],
        "cwe_ids": ["CWE-943"],
        "priority": "immediate",
        "estimated_effort": "1-2 hours per endpoint",
    },
    # ── XSS ────────────────────────────────────────────────────────────────
    "xss_reflected": {
        "summary": (
            "Encode/escape all user-controlled output in the correct context "
            "(HTML, JS, URL, CSS). Deploy Content-Security-Policy (CSP)."
        ),
        "detail": (
            "Reflected XSS occurs when user input is immediately returned in "
            "the response without proper encoding.\n"
            "- Use context-aware output encoding (HTML entity, JS string, URL)\n"
            "- Implement strict CSP: `default-src 'self'; script-src 'self'`\n"
            "- Use HttpOnly + Secure + SameSite flags on session cookies\n"
            "- Use templating engines with auto-escaping (Jinja2, React)\n"
            "- Validate input types where possible"
        ),
        "code_examples": [
            {
                "language": "python",
                "title": "Python/Flask/Jinja2",
                "vulnerable": (
                    '# VULNERABLE - unescaped output\n'
                    'return f"<p>Search: {request.args.get(\'q\')}</p>"\n'
                    'return Markup(user_input)  # Marks as safe — DANGEROUS'
                ),
                "fixed": (
                    '# FIXED - Jinja2 auto-escaping (default)\n'
                    'return render_template("search.html", query=request.args.get("q"))\n'
                    '# In template: {{ query }}  ← auto-escaped by Jinja2\n\n'
                    '# FIXED - manual escaping\n'
                    'from markupsafe import escape\n'
                    'safe_input = escape(user_input)'
                ),
            },
            {
                "language": "javascript",
                "title": "JavaScript / React",
                "vulnerable": (
                    '// VULNERABLE - innerHTML with user input\n'
                    'element.innerHTML = userInput;\n'
                    'document.write(location.search);'
                ),
                "fixed": (
                    '// FIXED - textContent (auto-escapes)\n'
                    'element.textContent = userInput;\n\n'
                    '// FIXED - React JSX (auto-escapes by default)\n'
                    'return <p>Search: {userInput}</p>;'
                ),
            },
            {
                "language": "generic",
                "title": "CSP Header",
                "vulnerable": "# No CSP header → XSS payload executes freely",
                "fixed": (
                    "# Strict CSP\n"
                    "Content-Security-Policy: default-src 'self'; "
                    "script-src 'self' 'nonce-{random}'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; "
                    "object-src 'none'; "
                    "base-uri 'self'"
                ),
            },
        ],
        "owasp_refs": ["OWASP A03:2021 — Injection", "OWASP XSS Prevention Cheat Sheet"],
        "cwe_ids": ["CWE-79"],
        "priority": "high",
        "estimated_effort": "2-4 hours",
    },
    "xss_stored": {
        "summary": (
            "Sanitize and encode ALL user input before storage AND before rendering. "
            "Deploy strict CSP. Consider using DOMPurify for rich text."
        ),
        "detail": (
            "Stored XSS persists in the database and executes for every user "
            "who views the affected page — higher impact than reflected XSS.\n"
            "- Sanitize input on storage (strip dangerous tags/attributes)\n"
            "- Encode output on rendering in the correct context\n"
            "- Use DOMPurify for user-generated HTML/rich text\n"
            "- Deploy strict CSP with nonces\n"
            "- Set HttpOnly, Secure, SameSite on all cookies"
        ),
        "code_examples": [
            {
                "language": "javascript",
                "title": "DOMPurify for rich text",
                "vulnerable": (
                    '// VULNERABLE - rendering raw HTML from DB\n'
                    'element.innerHTML = commentFromDB;'
                ),
                "fixed": (
                    '// FIXED - sanitize with DOMPurify before rendering\n'
                    'import DOMPurify from "dompurify";\n'
                    'element.innerHTML = DOMPurify.sanitize(commentFromDB);'
                ),
            },
        ],
        "owasp_refs": ["OWASP A03:2021 — Injection", "OWASP XSS Prevention Cheat Sheet"],
        "cwe_ids": ["CWE-79"],
        "priority": "immediate",
        "estimated_effort": "4-8 hours",
    },
    "xss_dom": {
        "summary": (
            "Avoid using dangerous DOM sinks (innerHTML, document.write, eval). "
            "Use textContent or framework-safe rendering."
        ),
        "detail": (
            "DOM-based XSS occurs entirely client-side when JavaScript reads "
            "untrusted data from sources (URL, postMessage) and passes it to "
            "dangerous sinks.\n"
            "- Replace innerHTML with textContent\n"
            "- Never use eval(), setTimeout(string), Function(string)\n"
            "- Validate postMessage origins\n"
            "- Use Trusted Types API where supported"
        ),
        "owasp_refs": ["OWASP DOM-based XSS Prevention Cheat Sheet"],
        "cwe_ids": ["CWE-79"],
        "priority": "high",
        "estimated_effort": "2-4 hours",
    },
    # ── SSRF ───────────────────────────────────────────────────────────────
    "ssrf": {
        "summary": (
            "Validate and restrict all URLs that the application fetches. "
            "Block internal/private IP ranges. Use allowlists for permitted domains."
        ),
        "detail": (
            "SSRF allows attackers to make the server send requests to internal "
            "services or arbitrary external destinations.\n"
            "- Maintain an allowlist of permitted domains/IPs\n"
            "- Block RFC 1918 private ranges (10.x, 172.16-31.x, 192.168.x)\n"
            "- Block cloud metadata endpoints (169.254.169.254)\n"
            "- Block localhost (127.0.0.1, ::1, 0.0.0.0)\n"
            "- Disable HTTP redirects or re-validate after redirect\n"
            "- Use a dedicated egress proxy with allowlisted destinations\n"
            "- DNS rebinding protection: resolve DNS before checking, then pin"
        ),
        "code_examples": [
            {
                "language": "python",
                "title": "Python SSRF prevention",
                "vulnerable": (
                    '# VULNERABLE - fetches any user-supplied URL\n'
                    'response = requests.get(user_url)'
                ),
                "fixed": (
                    '# FIXED - validate URL against allowlist\n'
                    'import ipaddress, socket\n'
                    'from urllib.parse import urlparse\n\n'
                    'ALLOWED_DOMAINS = {"api.example.com", "cdn.example.com"}\n'
                    'BLOCKED_RANGES = [\n'
                    '    ipaddress.ip_network("10.0.0.0/8"),\n'
                    '    ipaddress.ip_network("172.16.0.0/12"),\n'
                    '    ipaddress.ip_network("192.168.0.0/16"),\n'
                    '    ipaddress.ip_network("169.254.0.0/16"),\n'
                    '    ipaddress.ip_network("127.0.0.0/8"),\n'
                    ']\n\n'
                    'parsed = urlparse(user_url)\n'
                    'if parsed.hostname not in ALLOWED_DOMAINS:\n'
                    '    raise ValueError("Domain not allowed")\n'
                    'resolved = socket.getaddrinfo(parsed.hostname, None)\n'
                    'for _, _, _, _, addr in resolved:\n'
                    '    ip = ipaddress.ip_address(addr[0])\n'
                    '    if any(ip in net for net in BLOCKED_RANGES):\n'
                    '        raise ValueError("Internal IP not allowed")'
                ),
            },
        ],
        "owasp_refs": ["OWASP A10:2021 — SSRF", "OWASP SSRF Prevention Cheat Sheet"],
        "cwe_ids": ["CWE-918"],
        "priority": "immediate",
        "estimated_effort": "4-8 hours",
    },
    # ── SSTI ───────────────────────────────────────────────────────────────
    "ssti": {
        "summary": (
            "Never pass user input directly to template engines. Use sandboxed "
            "template environments and pre-compiled templates."
        ),
        "detail": (
            "Server-Side Template Injection can lead to Remote Code Execution.\n"
            "- Use pre-compiled/static templates, NOT string-based rendering\n"
            "- Enable sandboxing (Jinja2 SandboxedEnvironment)\n"
            "- Separate template logic from user data\n"
            "- Audit for render_template_string() or similar functions"
        ),
        "code_examples": [
            {
                "language": "python",
                "title": "Flask/Jinja2",
                "vulnerable": (
                    '# VULNERABLE - user input in template string\n'
                    'return render_template_string(user_input)\n'
                    'return render_template_string(f"Hello {name}")'
                ),
                "fixed": (
                    '# FIXED - pass as variable to pre-compiled template\n'
                    'return render_template("greeting.html", name=name)\n\n'
                    '# FIXED - sandboxed environment\n'
                    'from jinja2.sandbox import SandboxedEnvironment\n'
                    'env = SandboxedEnvironment()\n'
                    'template = env.from_string("Hello {{ name }}")\n'
                    'return template.render(name=name)'
                ),
            },
        ],
        "owasp_refs": ["OWASP A03:2021 — Injection"],
        "cwe_ids": ["CWE-1336"],
        "priority": "immediate",
        "estimated_effort": "2-4 hours",
    },
    # ── AUTHORIZATION ──────────────────────────────────────────────────────
    "idor": {
        "summary": (
            "Implement proper access control checks on every data access request. "
            "Use indirect references (UUIDs) instead of sequential IDs."
        ),
        "detail": (
            "Insecure Direct Object References allow users to access resources "
            "belonging to other users by manipulating identifiers.\n"
            "- Check ownership/permission on EVERY request, not just UI\n"
            "- Use UUIDs/GUIDs instead of sequential integers\n"
            "- Implement RBAC or ABAC at the service layer\n"
            "- Log and alert on access pattern anomalies"
        ),
        "owasp_refs": ["OWASP A01:2021 — Broken Access Control"],
        "cwe_ids": ["CWE-639"],
        "priority": "high",
        "estimated_effort": "4-8 hours (systemic fix)",
    },
    "bola": {
        "summary": (
            "Enforce object-level authorization on every API endpoint. "
            "Verify the requesting user owns or has permission to access the requested resource."
        ),
        "detail": (
            "Broken Object Level Authorization (BOLA / IDOR in APIs) is the #1 "
            "API vulnerability per OWASP API Security Top 10.\n"
            "- Add authorization middleware that checks resource ownership\n"
            "- Use UUIDs instead of predictable sequential IDs\n"
            "- Implement policy-based access at the data layer\n"
            "- Audit all endpoints that accept resource identifiers"
        ),
        "owasp_refs": ["OWASP API1:2023 — Broken Object Level Authorization"],
        "cwe_ids": ["CWE-639", "CWE-284"],
        "priority": "immediate",
        "estimated_effort": "1-2 days (systemic)",
    },
    "bfla": {
        "summary": (
            "Implement function-level access control. Deny by default and "
            "explicitly grant access to each role."
        ),
        "detail": (
            "Broken Function Level Authorization allows regular users to access "
            "admin or privileged API endpoints.\n"
            "- Implement RBAC with deny-by-default policy\n"
            "- Validate roles/permissions on every function call\n"
            "- Don't rely on hidden URLs as security (security through obscurity)\n"
            "- Log and alert administrative endpoint access"
        ),
        "owasp_refs": ["OWASP API5:2023 — Broken Function Level Authorization"],
        "cwe_ids": ["CWE-285"],
        "priority": "immediate",
        "estimated_effort": "1-2 days (systemic)",
    },
    "authentication_bypass": {
        "summary": (
            "Review and strengthen authentication mechanisms. Implement MFA "
            "and proper session management."
        ),
        "detail": (
            "Authentication bypass undermines the entire security model.\n"
            "- Never expose authentication logic to client-side manipulation\n"
            "- Use established auth frameworks (OAuth 2.0, OpenID Connect)\n"
            "- Implement MFA for sensitive operations\n"
            "- Use constant-time comparison for tokens/passwords\n"
            "- Enforce account lockout after failed attempts"
        ),
        "owasp_refs": ["OWASP A07:2021 — Identification and Authentication Failures"],
        "cwe_ids": ["CWE-287"],
        "priority": "immediate",
        "estimated_effort": "4-16 hours",
    },
    # ── MASS ASSIGNMENT ────────────────────────────────────────────────────
    "mass_assignment": {
        "summary": (
            "Use allowlists to explicitly define which fields can be updated by users. "
            "Never blindly bind request parameters to data models."
        ),
        "detail": (
            "Mass assignment occurs when an API automatically binds request "
            "parameters to internal model fields without filtering.\n"
            "- Define explicit allowlists of writable fields per endpoint\n"
            "- Use separate DTOs/schemas for input vs internal models\n"
            "- Never expose isAdmin, role, balance fields to user input\n"
            "- Audit model binding configuration in your framework"
        ),
        "code_examples": [
            {
                "language": "python",
                "title": "Python / Pydantic DTO",
                "vulnerable": (
                    '# VULNERABLE - accepts ALL fields from request\n'
                    'user.update(**request.json)\n'
                    'User.objects.filter(id=uid).update(**request.data)'
                ),
                "fixed": (
                    '# FIXED - explicit allowlist via Pydantic schema\n'
                    'class UserUpdate(BaseModel):\n'
                    '    name: str\n'
                    '    email: str\n'
                    '    # role, is_admin NOT included — cannot be set\n\n'
                    'data = UserUpdate(**request.json)\n'
                    'user.update(**data.model_dump())'
                ),
            },
            {
                "language": "javascript",
                "title": "Express.js / Mongoose",
                "vulnerable": (
                    '// VULNERABLE - passes all body params to model\n'
                    'User.findByIdAndUpdate(id, req.body);'
                ),
                "fixed": (
                    '// FIXED - pick only allowed fields\n'
                    'const { name, email } = req.body;\n'
                    'User.findByIdAndUpdate(id, { name, email });'
                ),
            },
        ],
        "owasp_refs": ["OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows"],
        "cwe_ids": ["CWE-915"],
        "priority": "high",
        "estimated_effort": "2-4 hours per model",
    },
    # ── DESERIALIZATION ────────────────────────────────────────────────────
    "insecure_deserialization": {
        "summary": (
            "Never deserialize untrusted data. Use safe serialization formats "
            "(JSON) instead of native object serialization."
        ),
        "detail": (
            "Insecure deserialization can lead to Remote Code Execution.\n"
            "- Replace Java ObjectInputStream, PHP unserialize(), Python pickle\n"
            "  with JSON or Protocol Buffers\n"
            "- If native serialization is required, use allowlist-based filtering\n"
            "- Validate integrity with HMAC before deserialization\n"
            "- Use Java's ObjectInputFilter (JEP 290+)\n"
            "- .NET: enable ViewState MAC validation"
        ),
        "code_examples": [
            {
                "language": "python",
                "title": "Python — avoid pickle",
                "vulnerable": (
                    '# VULNERABLE — pickle can execute arbitrary code\n'
                    'import pickle\n'
                    'data = pickle.loads(user_input)'
                ),
                "fixed": (
                    '# FIXED — use JSON for untrusted data\n'
                    'import json\n'
                    'data = json.loads(user_input)\n\n'
                    '# If pickle is unavoidable, use hmac validation:\n'
                    'import hmac, hashlib\n'
                    'expected = hmac.new(SECRET, payload, hashlib.sha256).digest()\n'
                    'if not hmac.compare_digest(signature, expected):\n'
                    '    raise ValueError("Tampered data")'
                ),
            },
            {
                "language": "java",
                "title": "Java — ObjectInputFilter",
                "vulnerable": (
                    '// VULNERABLE — deserializes any class\n'
                    'ObjectInputStream ois = new ObjectInputStream(input);\n'
                    'Object obj = ois.readObject();'
                ),
                "fixed": (
                    '// FIXED — allowlist filter (Java 9+)\n'
                    'ObjectInputFilter filter = ObjectInputFilter.Config\n'
                    '    .createFilter("com.myapp.models.*;!*");\n'
                    'ObjectInputStream ois = new ObjectInputStream(input);\n'
                    'ois.setObjectInputFilter(filter);\n'
                    'Object obj = ois.readObject();'
                ),
            },
        ],
        "owasp_refs": ["OWASP A08:2021 — Software and Data Integrity Failures"],
        "cwe_ids": ["CWE-502"],
        "priority": "immediate",
        "estimated_effort": "4-16 hours",
    },
    # ── CORS ───────────────────────────────────────────────────────────────
    "cors_misconfiguration": {
        "summary": (
            "Restrict Access-Control-Allow-Origin to specific trusted domains. "
            "Never reflect the Origin header or use wildcard (*) with credentials."
        ),
        "detail": (
            "CORS misconfiguration can allow any website to make authenticated "
            "requests on behalf of users.\n"
            "- Maintain an allowlist of trusted origins\n"
            "- Never use `Access-Control-Allow-Origin: *` with credentials\n"
            "- Never reflect the Origin header without validation\n"
            "- Be cautious with `Access-Control-Allow-Credentials: true`\n"
            "- Restrict allowed methods and headers"
        ),
        "code_examples": [
            {
                "language": "generic",
                "title": "Nginx CORS configuration",
                "vulnerable": (
                    '# VULNERABLE — reflects any origin\n'
                    'add_header Access-Control-Allow-Origin $http_origin;\n'
                    'add_header Access-Control-Allow-Credentials true;'
                ),
                "fixed": (
                    '# FIXED — allowlist check\n'
                    'set $cors_origin "";\n'
                    'if ($http_origin ~* "^https://(www\\.example\\.com|app\\.example\\.com)$") {\n'
                    '    set $cors_origin $http_origin;\n'
                    '}\n'
                    'add_header Access-Control-Allow-Origin $cors_origin;\n'
                    'add_header Access-Control-Allow-Credentials true;\n'
                    'add_header Vary Origin;'
                ),
            },
        ],
        "owasp_refs": ["OWASP A01:2021 — Broken Access Control"],
        "cwe_ids": ["CWE-942"],
        "priority": "high",
        "estimated_effort": "1-2 hours",
    },
    # ── OPEN REDIRECT ──────────────────────────────────────────────────────
    "open_redirect": {
        "summary": (
            "Validate redirect URLs against an allowlist. Remove user-controlled "
            "redirect targets or use indirect references."
        ),
        "detail": (
            "Open redirects enable phishing attacks using your domain's reputation.\n"
            "- Use an allowlist of permitted redirect destinations\n"
            "- Use indirect references (map ID → URL server-side)\n"
            "- If dynamic redirects are needed, validate scheme + host\n"
            "- Reject URLs with different schemes (javascript:, data:)"
        ),
        "owasp_refs": ["OWASP Unvalidated Redirects and Forwards Cheat Sheet"],
        "cwe_ids": ["CWE-601"],
        "priority": "medium",
        "estimated_effort": "1-2 hours",
    },
    # ── CRLF INJECTION ─────────────────────────────────────────────────────
    "crlf_injection": {
        "summary": (
            "Strip or encode CR (\\r) and LF (\\n) characters from user input "
            "before including in HTTP headers."
        ),
        "detail": (
            "CRLF injection allows header injection and HTTP response splitting.\n"
            "- Sanitize \\r\\n from all inputs used in HTTP headers\n"
            "- Use framework-provided safe header setting methods\n"
            "- Encode user input before including in Set-Cookie or Location headers"
        ),
        "owasp_refs": ["OWASP HTTP Response Splitting"],
        "cwe_ids": ["CWE-113"],
        "priority": "high",
        "estimated_effort": "1-2 hours",
    },
    # ── FILE INCLUSION ─────────────────────────────────────────────────────
    "local_file_inclusion": {
        "summary": (
            "Validate file paths against an allowlist. Remove path traversal "
            "sequences and use chroot/jail environments."
        ),
        "detail": (
            "LFI allows reading arbitrary server files and can escalate to RCE.\n"
            "- Use realpath() and verify the resolved path is under the allowed root\n"
            "- Maintain an allowlist of permitted file names\n"
            "- Strip ../ sequences recursively (handle double encoding)\n"
            "- Use chroot to restrict filesystem access\n"
            "- Disable PHP allow_url_include"
        ),
        "code_examples": [
            {
                "language": "python",
                "title": "Python path validation",
                "vulnerable": (
                    '# VULNERABLE\n'
                    'with open(f"/app/data/{filename}") as f:\n'
                    '    return f.read()'
                ),
                "fixed": (
                    '# FIXED — resolve and validate path\n'
                    'from pathlib import Path\n'
                    'BASE = Path("/app/data").resolve()\n'
                    'requested = (BASE / filename).resolve()\n'
                    'if not requested.is_relative_to(BASE):\n'
                    '    raise ValueError("Path traversal detected")\n'
                    'return requested.read_text()'
                ),
            },
        ],
        "owasp_refs": ["OWASP A01:2021 — Broken Access Control"],
        "cwe_ids": ["CWE-98"],
        "priority": "immediate",
        "estimated_effort": "2-4 hours",
    },
    # ── JWT ────────────────────────────────────────────────────────────────
    "jwt_vulnerability": {
        "summary": (
            "Use strong algorithms (RS256/ES256), validate all claims, "
            "and reject 'none' algorithm."
        ),
        "detail": (
            "JWT vulnerabilities can lead to authentication bypass.\n"
            "- Explicitly specify the algorithm server-side (reject 'none')\n"
            "- Use asymmetric algorithms (RS256, ES256) for public-facing APIs\n"
            "- Validate all claims: exp, nbf, iss, aud\n"
            "- Rotate signing keys periodically\n"
            "- Never store secrets in JWT payload (it's base64, not encrypted)"
        ),
        "owasp_refs": ["OWASP A07:2021 — Identification and Authentication Failures"],
        "cwe_ids": ["CWE-327", "CWE-347"],
        "priority": "high",
        "estimated_effort": "2-4 hours",
    },
    # ── SECURITY HEADERS ──────────────────────────────────────────────────
    "missing_security_header": {
        "summary": (
            "Add recommended security headers to all HTTP responses via "
            "web server or reverse proxy configuration."
        ),
        "detail": (
            "Security headers provide defense-in-depth against common attacks.\n"
            "- Content-Security-Policy: Prevent XSS and data injection\n"
            "- Strict-Transport-Security: Force HTTPS\n"
            "- X-Content-Type-Options: nosniff (prevent MIME sniffing)\n"
            "- X-Frame-Options: DENY/SAMEORIGIN (prevent clickjacking)\n"
            "- Referrer-Policy: strict-origin-when-cross-origin\n"
            "- Permissions-Policy: disable unnecessary browser features"
        ),
        "code_examples": [
            {
                "language": "generic",
                "title": "Nginx security headers",
                "vulnerable": "# No security headers configured",
                "fixed": (
                    "# Add to nginx server block\n"
                    'add_header Content-Security-Policy "default-src \'self\'" always;\n'
                    'add_header Strict-Transport-Security "max-age=31536000; '
                    'includeSubDomains" always;\n'
                    "add_header X-Content-Type-Options nosniff always;\n"
                    "add_header X-Frame-Options DENY always;\n"
                    "add_header Referrer-Policy strict-origin-when-cross-origin always;\n"
                    'add_header Permissions-Policy "camera=(), microphone=(), '
                    'geolocation=()" always;'
                ),
            },
        ],
        "owasp_refs": ["OWASP A05:2021 — Security Misconfiguration"],
        "cwe_ids": ["CWE-693"],
        "priority": "medium",
        "estimated_effort": "30 minutes",
    },
    "missing_csp": {
        "summary": (
            "Implement Content-Security-Policy to prevent XSS and data injection. "
            "Start with a restrictive policy and relax as needed."
        ),
        "detail": (
            "CSP is the most effective HTTP header for XSS prevention.\n"
            "- Start with: `default-src 'self'`\n"
            "- Use nonces for inline scripts: `script-src 'nonce-{random}'`\n"
            "- Add `report-uri` for monitoring violations\n"
            "- Test with `Content-Security-Policy-Report-Only` first"
        ),
        "owasp_refs": ["OWASP A05:2021 — Security Misconfiguration"],
        "cwe_ids": ["CWE-693"],
        "priority": "medium",
        "estimated_effort": "1-2 hours",
    },
    "missing_hsts": {
        "summary": (
            "Enable HSTS with `max-age=31536000; includeSubDomains; preload` "
            "to prevent SSL-stripping attacks."
        ),
        "detail": (
            "HSTS forces browsers to always use HTTPS.\n"
            "- Set max-age to at least 1 year (31536000)\n"
            "- Include includeSubDomains if all subdomains support HTTPS\n"
            "- Submit to the HSTS preload list for browser-level enforcement\n"
            "- Ensure all resources load over HTTPS before enabling"
        ),
        "owasp_refs": ["OWASP A05:2021 — Security Misconfiguration"],
        "cwe_ids": ["CWE-311"],
        "priority": "medium",
        "estimated_effort": "15 minutes",
    },
    "missing_x_frame_options": {
        "summary": (
            "Add `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent clickjacking. "
            "Alternatively use CSP `frame-ancestors` directive."
        ),
        "owasp_refs": ["OWASP Clickjacking Defense Cheat Sheet"],
        "cwe_ids": ["CWE-1021"],
        "priority": "medium",
        "estimated_effort": "15 minutes",
    },
    # ── SSL/TLS ────────────────────────────────────────────────────────────
    "ssl_tls_misconfiguration": {
        "summary": (
            "Disable TLS 1.0/1.1, use strong cipher suites, enable HSTS, "
            "and keep certificates current."
        ),
        "detail": (
            "TLS misconfigurations weaken transport security.\n"
            "- Minimum: TLS 1.2, prefer TLS 1.3\n"
            "- Disable weak ciphers (RC4, DES, 3DES, NULL, EXPORT)\n"
            "- Enable Perfect Forward Secrecy (ECDHE)\n"
            "- Use 2048+ bit RSA keys or 256+ bit ECDSA\n"
            "- Enable OCSP stapling\n"
            "- Monitor certificate expiration"
        ),
        "code_examples": [
            {
                "language": "generic",
                "title": "Nginx TLS configuration",
                "vulnerable": (
                    "# VULNERABLE — allows old protocols\n"
                    "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;"
                ),
                "fixed": (
                    "# FIXED — modern TLS only\n"
                    "ssl_protocols TLSv1.2 TLSv1.3;\n"
                    "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:"
                    "ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:"
                    "ECDHE-RSA-AES256-GCM-SHA384;\n"
                    "ssl_prefer_server_ciphers on;\n"
                    "ssl_session_timeout 1d;\n"
                    "ssl_session_cache shared:TLS:10m;\n"
                    "ssl_stapling on;\n"
                    "ssl_stapling_verify on;"
                ),
            },
        ],
        "owasp_refs": ["OWASP A02:2021 — Cryptographic Failures"],
        "cwe_ids": ["CWE-326", "CWE-327"],
        "priority": "high",
        "estimated_effort": "1-2 hours",
    },
    # ── INFORMATION DISCLOSURE ─────────────────────────────────────────────
    "information_disclosure": {
        "summary": (
            "Remove server version banners, disable directory listings, "
            "and suppress verbose error messages in production."
        ),
        "detail": (
            "Information disclosure helps attackers fingerprint technology stacks.\n"
            "- Remove Server header or set to generic value\n"
            "- Remove X-Powered-By header\n"
            "- Disable directory listings\n"
            "- Use custom error pages (no stack traces)\n"
            "- Remove HTML comments containing sensitive info\n"
            "- Restrict access to .git, .env, backup files"
        ),
        "code_examples": [
            {
                "language": "generic",
                "title": "Server hardening",
                "vulnerable": (
                    "# Nginx exposes version\n"
                    "Server: nginx/1.18.0\n"
                    "X-Powered-By: Express"
                ),
                "fixed": (
                    "# Nginx: hide version\n"
                    "server_tokens off;\n\n"
                    "# Express: remove header\n"
                    "app.disable('x-powered-by');\n\n"
                    "# Apache: suppress version\n"
                    "ServerTokens Prod\n"
                    "ServerSignature Off"
                ),
            },
        ],
        "owasp_refs": ["OWASP A05:2021 — Security Misconfiguration"],
        "cwe_ids": ["CWE-200"],
        "priority": "low",
        "estimated_effort": "30 minutes",
    },
    "sensitive_url": {
        "summary": (
            "Restrict access to administrative URLs, backup files, and debug endpoints "
            "using authentication and IP allowlists."
        ),
        "owasp_refs": ["OWASP A05:2021 — Security Misconfiguration"],
        "cwe_ids": ["CWE-200"],
        "priority": "medium",
        "estimated_effort": "30 minutes - 1 hour",
    },
    "sensitive_information": {
        "summary": (
            "Remove server version banners and internal path disclosures. "
            "Configure web servers to suppress technology fingerprinting headers."
        ),
        "owasp_refs": ["OWASP A05:2021 — Security Misconfiguration"],
        "cwe_ids": ["CWE-200"],
        "priority": "low",
        "estimated_effort": "30 minutes",
    },
    "server_header_disclosure": {
        "summary": (
            "Remove or obfuscate the Server header. "
            "Nginx: `server_tokens off;` Apache: `ServerTokens Prod`."
        ),
        "owasp_refs": ["OWASP A05:2021 — Security Misconfiguration"],
        "cwe_ids": ["CWE-200"],
        "priority": "low",
        "estimated_effort": "15 minutes",
    },
    # ── COOKIE ─────────────────────────────────────────────────────────────
    "insecure_cookie": {
        "summary": (
            "Set Secure, HttpOnly, and SameSite attributes on all session cookies. "
            "Ensure cookies are only transmitted over HTTPS."
        ),
        "detail": (
            "Insecure cookie attributes weaken session security.\n"
            "- Secure: only transmit over HTTPS\n"
            "- HttpOnly: prevent JavaScript access (XSS mitigation)\n"
            "- SameSite=Lax or Strict: prevent CSRF\n"
            "- Set proper expiration (session cookies for auth)\n"
            "- Use __Host- prefix for strongest cookie security"
        ),
        "owasp_refs": ["OWASP A07:2021 — Identification and Authentication Failures"],
        "cwe_ids": ["CWE-614"],
        "priority": "medium",
        "estimated_effort": "30 minutes",
    },
    # ── CVE / OUTDATED ─────────────────────────────────────────────────────
    "cve": {
        "summary": (
            "Update the affected software to the latest patched version. "
            "Apply vendor-recommended mitigations while scheduling the update."
        ),
        "detail": (
            "Known CVEs have published exploit code and are actively targeted.\n"
            "- Apply the vendor security patch immediately\n"
            "- If patching takes time, deploy WAF virtual patches\n"
            "- Subscribe to vendor security advisories\n"
            "- Implement automated dependency scanning (Dependabot, Snyk)"
        ),
        "owasp_refs": ["OWASP A06:2021 — Vulnerable and Outdated Components"],
        "cwe_ids": [],
        "priority": "immediate",
        "estimated_effort": "1-4 hours (depending on component)",
    },
    "outdated_software": {
        "summary": (
            "Update the software to the latest stable version. Implement "
            "automated patch management."
        ),
        "owasp_refs": ["OWASP A06:2021 — Vulnerable and Outdated Components"],
        "cwe_ids": ["CWE-1104"],
        "priority": "high",
        "estimated_effort": "1-4 hours",
    },
    # ── API ────────────────────────────────────────────────────────────────
    "api_misconfiguration": {
        "summary": (
            "Disable unnecessary API endpoints. Implement authentication, "
            "rate limiting, and input validation on all API routes."
        ),
        "owasp_refs": ["OWASP API Security Top 10"],
        "cwe_ids": ["CWE-284"],
        "priority": "high",
        "estimated_effort": "2-8 hours",
    },
    # ── HTTP METHOD ────────────────────────────────────────────────────────
    "dangerous_http_method": {
        "summary": (
            "Disable unnecessary HTTP methods (TRACE, PUT, DELETE, OPTIONS) "
            "at the web server level."
        ),
        "code_examples": [
            {
                "language": "generic",
                "title": "Nginx method restriction",
                "vulnerable": "# All methods allowed by default",
                "fixed": (
                    "# Only allow GET, POST, HEAD\n"
                    "if ($request_method !~ ^(GET|POST|HEAD)$ ) {\n"
                    "    return 405;\n"
                    "}"
                ),
            },
        ],
        "owasp_refs": ["OWASP A05:2021 — Security Misconfiguration"],
        "cwe_ids": ["CWE-749"],
        "priority": "medium",
        "estimated_effort": "15 minutes",
    },
    # ── RATE LIMITING ──────────────────────────────────────────────────────
    "rate_limit_bypass": {
        "summary": (
            "Implement robust server-side rate limiting. Use progressive delays, "
            "CAPTCHA, and account lockout."
        ),
        "detail": (
            "Rate limit bypass enables brute force and credential stuffing.\n"
            "- Implement rate limiting at the WAF/load balancer level\n"
            "- Use token bucket or sliding window algorithms\n"
            "- Rate limit by IP AND by account\n"
            "- Add CAPTCHA after N failed attempts\n"
            "- Implement progressive delays (exponential backoff)"
        ),
        "owasp_refs": ["OWASP A07:2021 — Identification and Authentication Failures"],
        "cwe_ids": ["CWE-307"],
        "priority": "medium",
        "estimated_effort": "2-4 hours",
    },
    # ── RACE CONDITION ─────────────────────────────────────────────────────
    "race_condition": {
        "summary": (
            "Implement proper locking (mutexes, DB locks) for critical operations. "
            "Use idempotency tokens."
        ),
        "detail": (
            "Race conditions in web apps can lead to double-spending, "
            "privilege escalation, or data corruption.\n"
            "- Use database-level locks (SELECT ... FOR UPDATE)\n"
            "- Implement idempotency tokens for state-changing requests\n"
            "- Use optimistic locking with version counters\n"
            "- Make critical operations atomic"
        ),
        "owasp_refs": ["OWASP Race Condition"],
        "cwe_ids": ["CWE-362"],
        "priority": "high",
        "estimated_effort": "4-8 hours per critical operation",
    },
    # ── HTTP REQUEST SMUGGLING ─────────────────────────────────────────────
    "http_request_smuggling": {
        "summary": (
            "Normalize Content-Length and Transfer-Encoding handling between "
            "front-end and back-end servers."
        ),
        "detail": (
            "Request smuggling exploits HTTP parsing differences.\n"
            "- Use HTTP/2 end-to-end (eliminates ambiguity)\n"
            "- Configure front-end to normalize ambiguous requests\n"
            "- Reject requests with both CL and TE headers\n"
            "- Keep all proxies and servers on the same HTTP implementation"
        ),
        "owasp_refs": ["OWASP HTTP Request Smuggling"],
        "cwe_ids": ["CWE-444"],
        "priority": "high",
        "estimated_effort": "2-4 hours",
    },
    "xxe": {
        "summary": "Disable external entity processing in XML parsers.",
        "detail": (
            "XML External Entity (XXE) injection exploits XML parsers that process "
            "external entity references.\n"
            "- Disable DTDs (DOCTYPE declarations) entirely if possible\n"
            "- Disable external entity and parameter entity processing\n"
            "- Use less complex data formats (JSON) where possible\n"
            "- Patch/upgrade XML processors and libraries\n"
            "- Implement server-side input validation and whitelisting"
        ),
        "owasp_refs": ["OWASP A05:2021 Security Misconfiguration"],
        "cwe_ids": ["CWE-611"],
        "priority": "high",
        "estimated_effort": "1-2 hours",
    },
    "file_upload": {
        "summary": "Validate file type, size, and content server-side before storing.",
        "detail": (
            "Insecure file upload allows attackers to upload malicious files.\n"
            "- Validate file extension against a whitelist (not blacklist)\n"
            "- Verify MIME type and magic bytes server-side\n"
            "- Store uploads outside the web root\n"
            "- Rename files with random names, strip original filename\n"
            "- Set Content-Disposition: attachment header\n"
            "- Implement file size limits\n"
            "- Scan uploaded files for malware"
        ),
        "owasp_refs": ["OWASP Unrestricted File Upload"],
        "cwe_ids": ["CWE-434"],
        "priority": "high",
        "estimated_effort": "2-4 hours",
    },
    "prototype_pollution": {
        "summary": "Sanitize user input to prevent JavaScript prototype chain manipulation.",
        "detail": (
            "Prototype pollution allows attackers to modify Object.prototype.\n"
            "- Freeze Object.prototype with Object.freeze()\n"
            "- Use Map instead of plain objects for user-controlled keys\n"
            "- Validate and sanitize all property keys (block __proto__, constructor, prototype)\n"
            "- Use Object.create(null) for lookup objects\n"
            "- Keep dependencies updated (lodash, jQuery, etc.)"
        ),
        "owasp_refs": ["OWASP Prototype Pollution"],
        "cwe_ids": ["CWE-1321"],
        "priority": "medium",
        "estimated_effort": "1-3 hours",
    },
    "business_logic": {
        "summary": "Implement server-side validation for all business rules and workflows.",
        "detail": (
            "Business logic flaws bypass intended application workflows.\n"
            "- Enforce all business rules server-side (not just client-side)\n"
            "- Implement proper state machine for multi-step processes\n"
            "- Validate sequence and completeness of workflow steps\n"
            "- Apply rate limiting and anomaly detection\n"
            "- Log and monitor unusual business flow patterns"
        ),
        "owasp_refs": ["OWASP Business Logic Vulnerabilities"],
        "cwe_ids": ["CWE-840"],
        "priority": "medium",
        "estimated_effort": "variable",
    },
}

# ── Alias mappings for fuzzy matching ──
_ALIASES: dict[str, str] = {
    "sqli": "sql_injection",
    "sql-injection": "sql_injection",
    "cmdi": "command_injection",
    "cmd_injection": "command_injection",
    "os_command_injection": "command_injection",
    "xss": "xss_reflected",
    "cross_site_scripting": "xss_reflected",
    "reflected_xss": "xss_reflected",
    "stored_xss": "xss_stored",
    "dom_xss": "xss_dom",
    "dom-based_xss": "xss_dom",
    "server_side_request_forgery": "ssrf",
    "server-side-template-injection": "ssti",
    "template_injection": "ssti",
    "insecure_direct_object_reference": "idor",
    "broken_object_level_authorization": "bola",
    "broken_function_level_authorization": "bfla",
    "auth_bypass": "authentication_bypass",
    "parameter_tampering": "mass_assignment",
    "deserialization": "insecure_deserialization",
    "cors": "cors_misconfiguration",
    "redirect": "open_redirect",
    "crlf": "crlf_injection",
    "lfi": "local_file_inclusion",
    "path_traversal": "local_file_inclusion",
    "file_inclusion": "local_file_inclusion",
    "jwt": "jwt_vulnerability",
    "security_header": "missing_security_header",
    "header_missing": "missing_security_header",
    "csp": "missing_csp",
    "hsts": "missing_hsts",
    "clickjacking": "missing_x_frame_options",
    "x_frame": "missing_x_frame_options",
    "ssl": "ssl_tls_misconfiguration",
    "tls": "ssl_tls_misconfiguration",
    "info_disclosure": "information_disclosure",
    "cookie": "insecure_cookie",
    "cookie_security": "insecure_cookie",
    "method": "dangerous_http_method",
    "http_method": "dangerous_http_method",
    "rate_limit": "rate_limit_bypass",
    "race": "race_condition",
    "smuggling": "http_request_smuggling",
    "request_smuggling": "http_request_smuggling",
    "outdated": "outdated_software",
    "version": "outdated_software",
    "api": "api_misconfiguration",
    "sensitive": "sensitive_information",
    # Scanner-produced types that need alias mapping
    "prototype_pollution": "prototype_pollution",  # Own category if exists, else generic
    "business_logic": "business_logic",  # Own category
    "bola": "bola",  # Broken Object Level Auth — has own remediation
    "bfla": "authentication_bypass",  # Broken Function Level Auth → auth bypass
    "nosql_injection": "sql_injection",  # Similar remediation approach
    "nosqli": "sql_injection",
    "xxe": "xxe",  # XML External Entity — own category
    "xml_external_entity": "xxe",
    "rce": "command_injection",  # Remote Code Execution → command injection
    "remote_code_execution": "command_injection",
    "directory_traversal": "local_file_inclusion",
    "file_upload": "file_upload",  # File upload bypass — own category
    "privilege_escalation": "idor",  # Often auth/IDOR related
    "parameter_pollution": "mass_assignment",
    "http_header_injection": "crlf_injection",
    "header_injection": "crlf_injection",
    "subdomain_takeover": "information_disclosure",
    "email_spoofing": "information_disclosure",
    "dns_misconfiguration": "information_disclosure",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_remediation(vuln_type: str) -> RemediationAdvice:
    """Get comprehensive remediation advice for a vulnerability type.

    Args:
        vuln_type: Vulnerability type identifier (e.g., "sql_injection", "xss_reflected").
                   Also accepts common aliases (e.g., "sqli", "xss", "ssrf").

    Returns:
        RemediationAdvice with summary, detail, code examples, and references.
    """
    # Normalize key
    key = vuln_type.lower().strip().replace("-", "_").replace(" ", "_")

    # Check aliases
    key = _ALIASES.get(key, key)

    # Try exact match
    data = _REMEDIATIONS.get(key)

    # No fuzzy fallback — wrong template is worse than generic advice
    if not data:
        logger.debug(f"No remediation template for vuln_type '{vuln_type}' (normalized: '{key}')")

    if not data:
        return RemediationAdvice(
            summary=(
                "Review and fix the identified vulnerability following "
                "security best practices."
            ),
            detail="",  # Empty so caller's fallback logic can activate
            priority="medium",
        )

    code_examples = []
    for ex in data.get("code_examples", []):
        code_examples.append(
            CodeExample(
                language=ex.get("language", "generic"),
                title=ex.get("title", ""),
                vulnerable=ex.get("vulnerable", ""),
                fixed=ex.get("fixed", ""),
            )
        )

    return RemediationAdvice(
        summary=data.get("summary", ""),
        detail=data.get("detail", ""),
        code_examples=code_examples,
        owasp_refs=data.get("owasp_refs", []),
        cwe_ids=data.get("cwe_ids", []),
        priority=data.get("priority", "medium"),
        estimated_effort=data.get("estimated_effort", ""),
    )


def format_remediation_markdown(advice: RemediationAdvice) -> str:
    """Format RemediationAdvice into a Markdown section for reports.

    Returns a Markdown string with summary, detail, code examples, and references.
    """
    lines: list[str] = []

    if advice.summary:
        lines.append(f"**Summary:** {advice.summary}")

    if advice.detail:
        lines.append(f"\n{advice.detail}")

    if advice.code_examples:
        lines.append("\n**Code Examples:**")
        for ex in advice.code_examples:
            if ex.title:
                lines.append(f"\n*{ex.title}:*")
            if ex.vulnerable:
                lines.append(f"\n```{ex.language}\n{ex.vulnerable}\n```")
            if ex.fixed:
                lines.append(f"\n```{ex.language}\n{ex.fixed}\n```")

    refs: list[str] = []
    if advice.owasp_refs:
        refs.extend(advice.owasp_refs)
    if advice.cwe_ids:
        refs.extend(advice.cwe_ids)
    if refs:
        lines.append("\n**References:** " + ", ".join(refs))

    if advice.priority:
        lines.append(f"\n**Priority:** {advice.priority.upper()}")
    if advice.estimated_effort:
        lines.append(f"**Estimated Effort:** {advice.estimated_effort}")

    return "\n".join(lines)


def get_remediation_text(vuln_type: str) -> str:
    """Convenience function: get formatted remediation text for a vuln type.

    Combines get_remediation() + format_remediation_markdown() for direct use
    in report generation.
    """
    advice = get_remediation(vuln_type)
    return format_remediation_markdown(advice)
