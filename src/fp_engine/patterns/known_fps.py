"""
WhiteHatHacker AI — Known False Positive Patterns

Her araç ve zafiyet türü için bilinen false positive kalıplarını
içeren veritabanı. Yeni bir bulgu geldiğinde bu kalıplarla
eşleşme kontrolü yapılır.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

class FPPattern(BaseModel):
    """Bilinen false positive kalıbı."""

    id: str = ""
    name: str = ""
    vuln_type: str = ""             # Etkili olduğu zafiyet türü ("*" = hepsi)
    source_tool: str = ""           # Hangi araçtan gelir ("*" = hepsi)
    description: str = ""

    # Eşleme kuralları
    match_rules: list[dict[str, str]] = Field(default_factory=list)
    # Her rule: {"field": "response_body|status_code|url|header|title|evidence",
    #            "operator": "contains|regex|equals|not_contains",
    #            "value": "pattern"}

    # Eşleşme durumunda
    action: str = "flag"            # flag (güven düşür) | dismiss (sil) | verify (ek doğrulama gerekli)
    confidence_penalty: int = -30   # güven skorundan düşülecek miktar
    reason: str = ""                # neden FP olduğu

    # Öğrenme
    times_matched: int = 0
    last_matched: str = ""


# ============================================================
# KNOWN FALSE POSITIVE DATABASE
# ============================================================

KNOWN_FP_PATTERNS: list[FPPattern] = [

    # ── SQL Injection FPs ───────────────────────────────────

    FPPattern(
        id="FP-SQLI-001",
        name="Generic SQL error page (not injectable)",
        vuln_type="sql_injection",
        source_tool="*",
        description="Application returns SQL error on any special character, but query is not actually injectable",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(syntax error|SQL syntax|mysql_fetch|pg_query)"},
            {"field": "evidence", "operator": "not_contains", "value": "UNION SELECT"},
            {"field": "evidence", "operator": "not_contains", "value": "extractvalue"},
        ],
        action="verify",
        confidence_penalty=-20,
        reason="SQL error message present but no actual data extraction or query manipulation confirmed",
    ),
    FPPattern(
        id="FP-SQLI-002",
        name="Boolean blind SQLi false trigger",
        vuln_type="sql_injection",
        source_tool="sqlmap",
        description="sqlmap reports boolean-based blind but page content varies naturally",
        match_rules=[
            {"field": "evidence", "operator": "contains", "value": "boolean-based blind"},
            {"field": "evidence", "operator": "not_contains", "value": "time-based"},
            {"field": "evidence", "operator": "not_contains", "value": "UNION"},
        ],
        action="verify",
        confidence_penalty=-25,
        reason="Boolean-based blind alone without time-based or UNION confirmation is unreliable",
    ),
    FPPattern(
        id="FP-SQLI-003",
        name="WAF blocked SQL payload",
        vuln_type="sql_injection",
        source_tool="*",
        description="WAF blocked the payload and returned custom error that mimics SQL response",
        match_rules=[
            {"field": "status_code", "operator": "equals", "value": "403"},
            {"field": "response_body", "operator": "regex", "value": r"(blocked|firewall|security|waf|forbidden)"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="Response is from WAF blocking, not from actual SQL injection success",
    ),

    # ── XSS FPs ─────────────────────────────────────────────

    FPPattern(
        id="FP-XSS-001",
        name="Reflected but HTML-encoded",
        vuln_type="xss_reflected",
        source_tool="*",
        description="Payload reflected in response but HTML entities are properly encoded",
        match_rules=[
            {"field": "response_body", "operator": "contains", "value": "&lt;script"},
            {"field": "response_body", "operator": "not_contains", "value": "<script"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="Payload is properly HTML-encoded in output — not exploitable",
    ),
    FPPattern(
        id="FP-XSS-002",
        name="XSS in non-HTML context (JSON/XML)",
        vuln_type="xss_reflected",
        source_tool="*",
        description="Payload reflected in JSON or XML response without HTML rendering",
        match_rules=[
            {"field": "header", "operator": "regex", "value": r"content-type:\s*(application/json|application/xml|text/xml)"},
        ],
        action="verify",
        confidence_penalty=-25,
        reason="Payload reflected in JSON/XML content type — not rendered as HTML by default",
    ),
    FPPattern(
        id="FP-XSS-003",
        name="CSP blocks execution",
        vuln_type="xss_reflected",
        source_tool="*",
        description="Reflected XSS present but strict CSP prevents actual execution",
        match_rules=[
            {"field": "header", "operator": "regex", "value": r"content-security-policy:.*script-src\s+'(none|self|nonce-)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Strong Content-Security-Policy may prevent XSS execution (still reportable with CSP bypass)",
    ),
    FPPattern(
        id="FP-XSS-004",
        name="XSS in 404 page irrelevant path",
        vuln_type="xss_reflected",
        source_tool="*",
        description="XSS reflected in custom 404 page only through URL path which is not user-accessible",
        match_rules=[
            {"field": "status_code", "operator": "equals", "value": "404"},
            {"field": "url", "operator": "regex", "value": r"/%3Cscript|/<script"},
        ],
        action="flag",
        confidence_penalty=-10,
        reason="XSS in 404 page — still valid but lower impact; some programs consider P4/P5",
    ),

    # ── SSRF FPs ────────────────────────────────────────────

    FPPattern(
        id="FP-SSRF-001",
        name="SSRF reported but no callback received",
        vuln_type="ssrf",
        source_tool="*",
        description="Tool flagged potential SSRF but no out-of-band callback was received",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "callback"},
            {"field": "evidence", "operator": "not_contains", "value": "DNS lookup"},
            {"field": "evidence", "operator": "not_contains", "value": "HTTP request received"},
            {"field": "evidence", "operator": "not_regex", "value": r"(?i)(169\.254|metadata|ami-id|internal|localhost response|cloud.metadata|instance.type)"},
        ],
        action="verify",
        confidence_penalty=-20,
        reason="SSRF not confirmed via OOB callback — needs manual verification",
    ),
    FPPattern(
        id="FP-SSRF-002",
        name="URL in response is not server-fetched",
        vuln_type="ssrf",
        source_tool="*",
        description="The URL appears in response but application didn't actually fetch it",
        match_rules=[
            {"field": "response_body", "operator": "regex", "value": r"(invalid url|bad request|url not allowed|scheme not supported)"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="Application returns error for the URL — may have URL validation in place",
    ),

    # ── Command Injection FPs ───────────────────────────────

    FPPattern(
        id="FP-CMDI-001",
        name="Time delay from network latency",
        vuln_type="command_injection",
        source_tool="*",
        description="Time-based detection triggered by network latency rather than actual sleep/delay execution",
        match_rules=[
            {"field": "evidence", "operator": "contains", "value": "time-based"},
            {"field": "evidence", "operator": "not_contains", "value": "consistent delay"},
        ],
        action="verify",
        confidence_penalty=-20,
        reason="Single time-based test may be affected by network jitter — needs multiple confirmations",
    ),
    FPPattern(
        id="FP-CMDI-002",
        name="WAF-blocked command payload",
        vuln_type="command_injection",
        source_tool="commix",
        description="WAF blocked the command injection payload",
        match_rules=[
            {"field": "status_code", "operator": "regex", "value": r"40[03]"},
            {"field": "response_body", "operator": "regex", "value": r"(blocked|firewall|security|access denied|waf)"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="Command injection payload was blocked by WAF/IPS",
    ),

    # ── SSTI FPs ────────────────────────────────────────────

    FPPattern(
        id="FP-SSTI-001",
        name="Math expression rendered by framework (not SSTI)",
        vuln_type="ssti",
        source_tool="*",
        description="{{7*7}}=49 rendered by client-side template engine (Angular, Vue) not server-side",
        match_rules=[
            {"field": "response_body", "operator": "contains", "value": "49"},
            {"field": "evidence", "operator": "regex", "value": r"(ng-app|vue|react|angular)"},
        ],
        action="verify",
        confidence_penalty=-20,
        reason="Expression evaluated by client-side framework — confirm server-side execution with {{config}} or similar",
    ),

    # ── CORS FPs ────────────────────────────────────────────

    FPPattern(
        id="FP-CORS-001",
        name="CORS wildcard without credentials",
        vuln_type="cors_misconfiguration",
        source_tool="*",
        description="Access-Control-Allow-Origin: * but Access-Control-Allow-Credentials is not true",
        match_rules=[
            {"field": "header", "operator": "contains", "value": "access-control-allow-origin: *"},
            {"field": "header", "operator": "not_contains", "value": "access-control-allow-credentials: true"},
        ],
        action="dismiss",
        confidence_penalty=-35,
        reason="Wildcard CORS without credentials is generally not exploitable for sensitive data theft",
    ),
    FPPattern(
        id="FP-CORS-002",
        name="CORS on public API without auth",
        vuln_type="cors_misconfiguration",
        source_tool="*",
        description="CORS configured on public, unauthenticated API endpoint",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(public|open|no.?auth)"},
            {"field": "header", "operator": "contains", "value": "access-control-allow-origin"},
        ],
        action="dismiss",
        confidence_penalty=-30,
        reason="CORS on public endpoints serving non-sensitive data is by design",
    ),

    # ── Open Redirect FPs ───────────────────────────────────

    FPPattern(
        id="FP-REDIR-001",
        name="Redirect to same domain",
        vuln_type="open_redirect",
        source_tool="*",
        description="Redirect goes to same domain or subdomain — not fully open",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"redirect.*same.?domain|internal redirect"},
        ],
        action="dismiss",
        confidence_penalty=-35,
        reason="Redirect stays within same domain — not an open redirect vulnerability",
    ),
    FPPattern(
        id="FP-REDIR-002",
        name="Login redirect with returnUrl",
        vuln_type="open_redirect",
        source_tool="*",
        description="Login page uses returnUrl/next parameter but validates against allowlist",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(login|signin|auth).*(return|next|redirect)"},
            {"field": "status_code", "operator": "regex", "value": r"(200|302)"},
            {"field": "evidence", "operator": "not_contains", "value": "external domain"},
        ],
        action="verify",
        confidence_penalty=-15,
        reason="Login redirect parameters may be validated — needs manual check",
    ),

    # ── SSL/TLS FPs ─────────────────────────────────────────

    FPPattern(
        id="FP-SSL-001",
        name="CDN/proxy SSL termination artifact",
        vuln_type="ssl_tls_misconfiguration",
        source_tool="*",
        description="SSL scan shows issues that are artifacts of CDN/load balancer SSL termination",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(cloudflare|akamai|cloudfront|fastly|incapsula)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="SSL configuration may reflect CDN/proxy settings, not the origin server",
    ),
    FPPattern(
        id="FP-SSL-002",
        name="Deprecated TLS 1.0/1.1 on non-critical endpoint",
        vuln_type="ssl_tls_misconfiguration",
        source_tool="*",
        description="TLS 1.0/1.1 supported but endpoint serves no sensitive data",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"TLS (1\.0|1\.1)"},
        ],
        action="flag",
        confidence_penalty=-10,
        reason="Deprecated TLS version — valid finding but typically lower severity",
    ),

    # ── Generic FPs ─────────────────────────────────────────

    FPPattern(
        id="FP-GEN-001",
        name="Honeypot / CTF-style response",
        vuln_type="*",
        source_tool="*",
        description="Response appears to be from a honeypot or CTF challenge, not real application",
        match_rules=[
            {"field": "response_body", "operator": "regex", "value": r"(honeypot|canary|tarpit|flag\{|CTF)"},
        ],
        action="dismiss",
        confidence_penalty=-50,
        reason="Response indicates honeypot or CTF environment — not a real vulnerability",
    ),
    FPPattern(
        id="FP-GEN-002",
        name="Custom error handler masks real response",
        vuln_type="*",
        source_tool="*",
        description="Application returns same custom error page for all invalid inputs",
        match_rules=[
            {"field": "response_body", "operator": "regex",
             "value": r"(sorry.*went wrong|error occurred|please try again|unexpected error)"},
            {"field": "status_code", "operator": "regex", "value": r"(200|500)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Generic error response may hide actual behavior — needs deeper investigation",
    ),
    FPPattern(
        id="FP-GEN-003",
        name="Rate limited / captcha response",
        vuln_type="*",
        source_tool="*",
        description="Scanner triggered rate limiting or captcha",
        match_rules=[
            {"field": "status_code", "operator": "equals", "value": "429"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="Response is rate limiting, not vulnerability indicator",
    ),
    FPPattern(
        id="FP-GEN-004",
        name="Cloudflare challenge page",
        vuln_type="*",
        source_tool="*",
        description="Response is Cloudflare JavaScript challenge, not real application response",
        match_rules=[
            {"field": "response_body", "operator": "regex", "value": r"(cf-browser-verification|challenge-platform|jschl)"},
            {"field": "header", "operator": "contains", "value": "cf-ray"},
        ],
        action="dismiss",
        confidence_penalty=-45,
        reason="Cloudflare challenge page — scanner was blocked, results unreliable",
    ),

    # ── Nuclei False Alerts ────────────────────────────────
    FPPattern(
        id="FP-NUCLEI-001",
        name="Nuclei tech-detect info tag",
        vuln_type="*",
        source_tool="nuclei",
        description="Nuclei technology detection templates report info-only results",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)tech-detect|technology-detect"},
        ],
        action="dismiss",
        confidence_penalty=-50,
        reason="Technology detection is informational, not a vulnerability",
    ),
    FPPattern(
        id="FP-NUCLEI-002",
        name="Nuclei deprecated TLS behind CDN",
        vuln_type="ssl_tls_misconfiguration",
        source_tool="nuclei",
        description="TLS version finding when CDN/proxy terminates TLS",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)tls|ssl|deprecated"},
            {"field": "header", "operator": "regex", "value": r"(?i)cf-ray|x-cdn|x-cache|akamai|fastly"},
        ],
        action="dismiss",
        confidence_penalty=-35,
        reason="CDN/proxy handles TLS termination — finding reflects CDN config, not origin",
    ),
    FPPattern(
        id="FP-NUCLEI-003",
        name="Nuclei robots.txt / security.txt info",
        vuln_type="information_disclosure",
        source_tool="nuclei",
        description="Standard robots.txt or security.txt file detected",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(?i)/(robots\.txt|\.well-known/security\.txt)"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="robots.txt/security.txt are standard, expected files",
    ),

    # ── SearchSploit Noise ─────────────────────────────────
    FPPattern(
        id="FP-SPLOIT-001",
        name="Searchsploit generic version match",
        vuln_type="*",
        source_tool="searchsploit",
        description="SearchSploit matches on generic version without specific CVE validation",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "CVE-"},
            {"field": "title", "operator": "regex", "value": r"(?i)searchsploit|exploitdb"},
        ],
        action="flag",
        confidence_penalty=-35,
        reason="SearchSploit version match without verified CVE — needs manual confirmation",
    ),
    FPPattern(
        id="FP-SPLOIT-002",
        name="Searchsploit DoS-only exploit",
        vuln_type="*",
        source_tool="searchsploit",
        description="SearchSploit returned DoS exploit which is out of scope for bug bounty",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)denial.of.service|buffer.overflow|crash|dos"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="DoS/crash exploits are typically out of scope for bug bounty programs",
    ),

    # ── WAF Artifact Patterns ──────────────────────────────
    FPPattern(
        id="FP-WAF-001",
        name="Akamai WAF block",
        vuln_type="*",
        source_tool="*",
        description="Response is Akamai WAF block page, not real vulnerability",
        match_rules=[
            {"field": "header", "operator": "regex", "value": r"(?i)x-akamai|akamaighost"},
            {"field": "status_code", "operator": "equals", "value": "403"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="Akamai WAF blocked the request — tool output unreliable",
    ),
    FPPattern(
        id="FP-WAF-002",
        name="AWS WAF block",
        vuln_type="*",
        source_tool="*",
        description="Response contains AWS WAF block indicators",
        match_rules=[
            {"field": "response_body", "operator": "regex", "value": r"(?i)(aws|waf).*request.blocked|x-amzn-waf"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="AWS WAF blocked the scan request",
    ),
    FPPattern(
        id="FP-WAF-003",
        name="ModSecurity block",
        vuln_type="*",
        source_tool="*",
        description="ModSecurity / OWASP CRS blocked payload",
        match_rules=[
            {"field": "response_body", "operator": "regex", "value": r"(?i)mod_security|modsecurity|OWASP.CRS"},
        ],
        action="dismiss",
        confidence_penalty=-35,
        reason="ModSecurity WAF blocked the payload",
    ),

    # ── CDN Artifacts ──────────────────────────────────────
    FPPattern(
        id="FP-CDN-001",
        name="CDN default page",
        vuln_type="*",
        source_tool="*",
        description="Response is CDN default/parking page",
        match_rules=[
            {"field": "response_body", "operator": "regex",
             "value": r"(?i)(fastly|cloudflare|akamai|cloudfront).*error|host.not.routed"},
        ],
        action="dismiss",
        confidence_penalty=-45,
        reason="Response from CDN default page, not actual application",
    ),
    FPPattern(
        id="FP-CDN-002",
        name="CDN edge cache response",
        vuln_type="*",
        source_tool="*",
        description="Finding from cached CDN response that may not reflect actual behavior",
        match_rules=[
            {"field": "header", "operator": "regex", "value": r"(?i)x-cache:\s*HIT|age:\s*[1-9]\d{3,}"},
        ],
        action="flag",
        confidence_penalty=-10,
        reason="Response served from CDN cache — payload may not have reached origin",
    ),

    # ── CMS False Positives ────────────────────────────────
    FPPattern(
        id="FP-CMS-001",
        name="WordPress version disclosure (readme.html)",
        vuln_type="information_disclosure",
        source_tool="*",
        description="WordPress readme.html version disclosure is not a real vulnerability",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(?i)readme\.html|license\.txt"},
            {"field": "title", "operator": "regex", "value": r"(?i)wordpress|version.disclos"},
        ],
        action="dismiss",
        confidence_penalty=-35,
        reason="Standard WordPress file, not a security vulnerability",
    ),
    FPPattern(
        id="FP-CMS-002",
        name="WordPress xmlrpc.php default",
        vuln_type="*",
        source_tool="*",
        description="xmlrpc.php returns method list but is often disabled or rate-limited",
        match_rules=[
            {"field": "url", "operator": "contains", "value": "xmlrpc.php"},
            {"field": "status_code", "operator": "equals", "value": "200"},
        ],
        action="verify",
        confidence_penalty=-15,
        reason="xmlrpc.php exists but may be disabled by plugin or WAF",
    ),
    FPPattern(
        id="FP-CMS-003",
        name="WordPress user enumeration via REST API",
        vuln_type="information_disclosure",
        source_tool="*",
        description="wp-json/wp/v2/users is standard public API on many WordPress sites",
        match_rules=[
            {"field": "url", "operator": "contains", "value": "wp/v2/users"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="WordPress REST user endpoint is public by default, low severity",
    ),

    # ── CRLF / Header Injection ────────────────────────────
    FPPattern(
        id="FP-CRLF-001",
        name="CRLF not reflected in response header",
        vuln_type="crlf_injection",
        source_tool="*",
        description="CRLF payload injected but no new header appeared in response",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "Injected-Header"},
            {"field": "evidence", "operator": "not_contains", "value": "\\r\\n"},
        ],
        action="verify",
        confidence_penalty=-25,
        reason="No evidence of injected header in response — needs re-verification",
    ),

    # ── LFI Path Traversal ─────────────────────────────────
    FPPattern(
        id="FP-LFI-001",
        name="LFI blocked by WAF / 403",
        vuln_type="lfi",
        source_tool="*",
        description="Path traversal payload returned 403 indicating WAF/ACL block",
        match_rules=[
            {"field": "status_code", "operator": "equals", "value": "403"},
        ],
        action="dismiss",
        confidence_penalty=-35,
        reason="403 response suggests WAF blocked the path traversal attempt",
    ),

    # ── IDOR without proof ─────────────────────────────────
    FPPattern(
        id="FP-IDOR-001",
        name="IDOR same response for different IDs",
        vuln_type="idor",
        source_tool="*",
        description="Different resource IDs returned identical response",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)same.response|identical|no.difference"},
        ],
        action="dismiss",
        confidence_penalty=-30,
        reason="Same response for different IDs indicates no actual IDOR",
    ),

    # ── Timing-based without confirmation ──────────────────
    FPPattern(
        id="FP-TIME-001",
        name="Time-based detection single measurement",
        vuln_type="*",
        source_tool="*",
        description="Time-based detection with only one measurement (network jitter)",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)time.based|sleep|delay|benchmark"},
            {"field": "evidence", "operator": "not_contains", "value": "confirmed"},
        ],
        action="verify",
        confidence_penalty=-20,
        reason="Single time-based measurement may be network latency, not vulnerability",
    ),

    # ── Information disclosure low-value ───────────────────
    FPPattern(
        id="FP-INFO-001",
        name="Server header version disclosure",
        vuln_type="information_disclosure",
        source_tool="*",
        description="Server version header is extremely common and rarely actionable",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)server.header|server.version.disclos"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="Server version header is informational only, not reportable on most programs",
    ),
    FPPattern(
        id="FP-INFO-002",
        name="Missing security header (low severity)",
        vuln_type="information_disclosure",
        source_tool="*",
        description="Missing security headers like X-Frame-Options are low/info severity",
        match_rules=[
            {"field": "title", "operator": "regex",
             "value": r"(?i)missing.*(x-frame|x-content-type|referrer-policy|permissions-policy)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Missing security headers are rarely accepted on bug bounty programs",
    ),

    # ── Open redirect to same origin ───────────────────────
    FPPattern(
        id="FP-REDIR-003",
        name="Open redirect to subdomain of same org",
        vuln_type="open_redirect",
        source_tool="*",
        description="Redirect target is a subdomain of the same organization",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)redirect.*same.org|redirect.*subdomain"},
        ],
        action="dismiss",
        confidence_penalty=-30,
        reason="Redirect within same organization domain is not exploitable",
    ),

    # ── Brain Hypothesis FPs ───────────────────────────────

    FPPattern(
        id="FP-BRAIN-001",
        name="Unverified brain hypothesis",
        vuln_type="*",
        source_tool="brain_analysis",
        description="Brain-generated hypothesis without tool verification",
        match_rules=[
            {"field": "finding_type", "operator": "equals", "value": "hypothesis"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="Brain hypothesis not verified by any scanner — treat as unconfirmed",
    ),
    FPPattern(
        id="FP-BRAIN-002",
        name="Brain hypothesis with needs_verification tag",
        vuln_type="*",
        source_tool="brain_analysis",
        description="Brain finding explicitly tagged as needing verification",
        match_rules=[
            {"field": "tags", "operator": "contains", "value": "needs_verification"},
        ],
        action="verify",
        confidence_penalty=-20,
        reason="Finding explicitly marked as needing further verification",
    ),

    # ── CORS without credentials ───────────────────────────

    FPPattern(
        id="FP-CORS-003",
        name="CORS reflected origin without ACAC",
        vuln_type="cors_misconfiguration",
        source_tool="*",
        description="Origin reflected but Access-Control-Allow-Credentials is absent or false",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)ACAC.*false|credentials NOT sent|without.*credential"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Without credentials, CORS is limited to reading public data cross-origin",
    ),

    # ── JWT informational FPs ──────────────────────────────

    FPPattern(
        id="FP-JWT-001",
        name="JWT uses HS256 (not a vulnerability)",
        vuln_type="jwt",
        source_tool="*",
        description="JWT using HMAC-SHA256 is standard, not a weakness",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)jwt.*hs256|weak.*algorithm.*hs256"},
            {"field": "evidence", "operator": "not_contains", "value": "none"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="HS256 is the default and secure JWT algorithm — not a vulnerability",
    ),
    FPPattern(
        id="FP-JWT-002",
        name="JWT expiration warning (informational)",
        vuln_type="jwt",
        source_tool="*",
        description="Long JWT expiration time flagged as issue but not exploitable",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)jwt.*expir|token.*long.*life"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Long token expiration is a best-practice issue, not an exploitable vulnerability",
    ),

    # ── GraphQL introspection informational ────────────────

    FPPattern(
        id="FP-GQL-001",
        name="GraphQL introspection enabled (common in dev)",
        vuln_type="graphql",
        source_tool="*",
        description="GraphQL introspection is often intentional, especially on public APIs",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)graphql.*introspection.*enabled"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="GraphQL introspection is informational — many APIs leave it enabled intentionally",
    ),
    FPPattern(
        id="FP-GQL-002",
        name="GraphQL field suggestion (not a vuln)",
        vuln_type="graphql",
        source_tool="*",
        description="GraphQL field suggestion is a feature, rarely exploitable",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)graphql.*field.*suggest|graphql.*type.*enum"},
        ],
        action="dismiss",
        confidence_penalty=-30,
        reason="Field suggestions are a GraphQL feature, not a vulnerability",
    ),

    # ── Deserialization FPs ────────────────────────────────

    FPPattern(
        id="FP-DESER-001",
        name="Deserialization detected in standard framework",
        vuln_type="deserialization",
        source_tool="*",
        description="Serialized data detected but using standard framework with safe defaults",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)viewstate|__VIEWSTATE|csrf.*token.*serializ"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="ASP.NET ViewState and similar framework serialization uses MAC validation by default",
    ),

    # ── Race condition timing FPs ──────────────────────────

    FPPattern(
        id="FP-RACE-001",
        name="Race condition with insufficient evidence",
        vuln_type="race_condition",
        source_tool="*",
        description="Race condition detected but without actual duplicate resource creation proof",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "duplicate"},
            {"field": "evidence", "operator": "not_contains", "value": "extra"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Race condition without proof of duplicate resources — may be timing jitter",
    ),

    # ── Nuclei tech-detect FPs ─────────────────────────────

    FPPattern(
        id="FP-NUCLEI-TECH-001",
        name="Nuclei tech-detect template (informational only)",
        vuln_type="*",
        source_tool="nuclei",
        description="Nuclei technology detection templates report info, not vulnerabilities",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)tech-detect|technology.*detect|fingerprint"},
            {"field": "evidence", "operator": "regex", "value": r"(?i)template-id.*tech-detect|technologies/"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="Technology detection is informational, not a vulnerability finding",
    ),

    # ── SearchSploit noise ─────────────────────────────────

    FPPattern(
        id="FP-SEARCHSPLOIT-001",
        name="SearchSploit version-only match (no verification)",
        vuln_type="*",
        source_tool="searchsploit",
        description="SearchSploit match based on version string without actual exploitation",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "confirmed"},
            {"field": "evidence", "operator": "not_contains", "value": "exploited"},
        ],
        action="flag",
        confidence_penalty=-30,
        reason="Version-based CVE match without exploitation proof — may be patched or mitigated",
    ),

    # ── Missing security header chain redundancy ───────────

    FPPattern(
        id="FP-HEADER-001",
        name="Missing header on CDN-served static content",
        vuln_type="missing_security_header",
        source_tool="*",
        description="Missing security headers on static/CDN content are often CDN-level, not app-level",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(?i)\.(css|js|png|jpg|gif|svg|woff2?|ico|webp)(\?|$)"},
        ],
        action="dismiss",
        confidence_penalty=-30,
        reason="Missing headers on static assets are CDN artifacts, not application vulnerabilities",
    ),
    FPPattern(
        id="FP-HEADER-002",
        name="Missing X-Frame-Options when CSP frame-ancestors present",
        vuln_type="missing_security_header",
        source_tool="*",
        description="X-Frame-Options is superseded by CSP frame-ancestors directive",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)x-frame-options|clickjacking"},
            {"field": "header", "operator": "contains", "value": "frame-ancestors"},
        ],
        action="dismiss",
        confidence_penalty=-35,
        reason="CSP frame-ancestors supersedes X-Frame-Options — not a real missing header",
    ),

    # ── Cache poisoning CDN FPs ────────────────────────────

    FPPattern(
        id="FP-CACHE-001",
        name="Cache poisoning on uncacheable response",
        vuln_type="cache_poisoning",
        source_tool="*",
        description="Cache poisoning reported but response has no-cache or private directives",
        match_rules=[
            {"field": "header", "operator": "regex", "value": r"(?i)cache-control.*(no-cache|no-store|private)"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="Response is explicitly uncacheable — cache poisoning unlikely to persist",
    ),

    # ── Prototype pollution FPs ────────────────────────────

    FPPattern(
        id="FP-PROTO-001",
        name="Prototype pollution without DOM impact proof",
        vuln_type="prototype_pollution",
        source_tool="*",
        description="__proto__ parameter reflected but no DOM/XSS impact demonstrated",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "alert"},
            {"field": "evidence", "operator": "not_contains", "value": "document."},
            {"field": "evidence", "operator": "not_contains", "value": "XSS"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Prototype pollution without demonstrated security impact is informational",
    ),

    # ── Subdomain takeover FPs ─────────────────────────────

    FPPattern(
        id="FP-TAKEOVER-001",
        name="Subdomain takeover CNAME with active service",
        vuln_type="subdomain_takeover",
        source_tool="*",
        description="CNAME points to service that is actively responding (not dangling)",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)status.*(200|301|302|403)"},
            {"field": "evidence", "operator": "not_contains", "value": "nxdomain"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Service responding normally — CNAME is not dangling (takeover unlikely)",
    ),

    # ── Dalfox reflective FP ──────────────────────────────

    FPPattern(
        id="FP-DALFOX-001",
        name="Dalfox reflected parameter (HTML-encoded)",
        vuln_type="xss",
        source_tool="dalfox",
        description="Dalfox reports reflection but characters are HTML-entity encoded",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"&lt;|&gt;|&amp;|&quot;|&#"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Reflected content is HTML-encoded — XSS payload will not execute",
    ),

    # ── Nikto noise ────────────────────────────────────────

    FPPattern(
        id="FP-NIKTO-001",
        name="Nikto OSVDB entry (outdated database)",
        vuln_type="*",
        source_tool="nikto",
        description="Nikto references OSVDB (defunct since 2016) — likely outdated",
        match_rules=[
            {"field": "evidence", "operator": "contains", "value": "OSVDB"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="OSVDB has been defunct since 2016 — finding may be outdated or irrelevant",
    ),
    FPPattern(
        id="FP-NIKTO-002",
        name="Nikto directory listing on intentional index",
        vuln_type="*",
        source_tool="nikto",
        description="Directory listing reported but may be intentional (icons, static assets)",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(?i)/(icons|images|static|assets|css|js|fonts)/?$"},
            {"field": "title", "operator": "regex", "value": r"(?i)directory.*list|index.*of"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Directory listing on static asset paths is often intentional",
    ),

    # ── CRLF injection FPs ─────────────────────────────────

    FPPattern(
        id="FP-CRLF-002",
        name="CRLF reflected but sanitized by proxy/CDN",
        vuln_type="crlf_injection",
        source_tool="*",
        description="CRLF characters in URL are stripped or encoded by proxy/CDN layer",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)%0[dD].*encoded|crlf.*stripped|header.*not.*injected"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Proxy/CDN layer strips CRLF characters — injection does not reach server",
    ),

    # ── LFI/path traversal FPs ─────────────────────────────

    FPPattern(
        id="FP-LFI-003",
        name="LFI path traversal blocked by WAF",
        vuln_type="lfi",
        source_tool="*",
        description="Path traversal payload blocked — WAF or application filter detected ../",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)403|blocked|forbidden|waf.*detect"},
            {"field": "evidence", "operator": "contains", "value": "../"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Path traversal attempts blocked by WAF/filter — LFI not confirmed",
    ),
    FPPattern(
        id="FP-LFI-002",
        name="LFI without file content evidence",
        vuln_type="lfi",
        source_tool="*",
        description="LFI detection without actual file content (e.g. /etc/passwd) in response",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "root:"},
            {"field": "evidence", "operator": "not_regex", "value": r"(\\[boot|extension|fonts|mail\\]|php_|allow_url)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="LFI finding without actual file content in response — detection may be behavioral only",
    ),

    # ── IDOR FPs ───────────────────────────────────────────

    FPPattern(
        id="FP-IDOR-002",
        name="IDOR tested on public endpoint",
        vuln_type="idor",
        source_tool="*",
        description="Object reference tested but endpoint returns public data to any user",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)public.*endpoint|public.*api|no.*auth.*required"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Public API endpoint returns same data regardless of user — not an access control issue",
    ),

    # ── Info disclosure FPs ────────────────────────────────

    FPPattern(
        id="FP-INFO-003",
        name="Server version in header (informational only)",
        vuln_type="information_disclosure",
        source_tool="*",
        description="Server version header is informational, not a vulnerability by itself",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)server.*version|version.*disclosure"},
            {"field": "evidence", "operator": "not_contains", "value": "CVE"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Server version disclosure is informational — real severity depends on known CVEs",
    ),
    FPPattern(
        id="FP-INFO-004",
        name="Sensitive path returns 403/404 (not exposed)",
        vuln_type="information_disclosure",
        source_tool="*",
        description="Sensitive file path discovered but access is denied",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)status.*(403|404|401)"},
            {"field": "title", "operator": "regex", "value": r"(?i)sensitive.*file|backup.*file|admin.*panel"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Path discovered but access denied — information disclosure without actual data leak",
    ),

    # ── HTTP method checker FPs ────────────────────────────

    FPPattern(
        id="FP-METHOD-001",
        name="OPTIONS method enabled (standard CORS preflight)",
        vuln_type="http_method",
        source_tool="*",
        description="OPTIONS method is required for CORS preflight — not a vulnerability",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)OPTIONS.*method.*enabled|unsafe.*method.*OPTIONS"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="OPTIONS is required for CORS preflight requests — standard browser behavior",
    ),
    FPPattern(
        id="FP-METHOD-002",
        name="TRACE method but no XST evidence",
        vuln_type="http_method",
        source_tool="*",
        description="TRACE method detected but no Cross-Site Tracing demonstrated",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)TRACE.*method|unsafe.*method.*TRACE"},
            {"field": "evidence", "operator": "not_contains", "value": "cookie"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="TRACE method without credential reflection proof — modern browsers block XST",
    ),

    # ── WAF/CDN artifact FPs ───────────────────────────────

    FPPattern(
        id="FP-WAF-004",
        name="WAF challenge page misidentified as finding",
        vuln_type="*",
        source_tool="*",
        description="WAF challenge/captcha page interpreted as vulnerability evidence",
        match_rules=[
            {"field": "evidence", "operator": "regex",
             "value": r"(?i)challenge-platform|captcha|cf-chl-bypass|ray.id|attention required"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="Response is a WAF challenge page, not genuine vulnerability evidence",
    ),

    # ── SSTI FPs ──────────────────────────────────────────

    FPPattern(
        id="FP-SSTI-002",
        name="SSTI detection without math evaluation proof",
        vuln_type="ssti",
        source_tool="*",
        description="Template injection detected but no evidence of expression evaluation",
        match_rules=[
            {"field": "evidence", "operator": "not_regex", "value": r"\b(49|7\*7|id=|uid=)\b"},
            {"field": "evidence", "operator": "not_contains", "value": "{{"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="SSTI detection without evaluated expression in response body",
    ),

    # ── SSRF FPs ──────────────────────────────────────────

    FPPattern(
        id="FP-SSRF-003",
        name="SSRF detected via status code change only",
        vuln_type="ssrf",
        source_tool="*",
        description="SSRF detection based on status code delta without OOB callback or body evidence",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "callback"},
            {"field": "evidence", "operator": "not_contains", "value": "oob"},
            {"field": "evidence", "operator": "not_contains", "value": "interact"},
            {"field": "evidence", "operator": "not_regex", "value": r"(?i)(169\.254|metadata|internal|localhost response)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="SSRF without OOB confirmation or internal content — may be false positive",
    ),
    FPPattern(
        id="FP-SSRF-004",
        name="SSRF URL in non-fetchable parameter",
        vuln_type="ssrf",
        source_tool="*",
        description="URL injected into parameter that is not server-side fetched (e.g. client-side redirect)",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(?i)(redirect|return|next|goto|continue|callback)="},
        ],
        action="flag",
        confidence_penalty=-10,
        reason="Parameter name suggests client-side redirect, not server-side fetch (SSRF less likely)",
    ),

    # ── RCE FPs ────────────────────────────────────────────

    FPPattern(
        id="FP-RCE-001",
        name="RCE without command output evidence",
        vuln_type="rce",
        source_tool="*",
        description="Command injection detection without actual command output in response",
        match_rules=[
            {"field": "evidence", "operator": "not_regex", "value": r"(?i)(root:|uid=|id=\d|whoami|Linux|Windows)"},
            {"field": "evidence", "operator": "not_contains", "value": "callback"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="RCE detection without command execution proof in response body",
    ),

    # ── XXE FPs ────────────────────────────────────────────

    FPPattern(
        id="FP-XXE-001",
        name="XXE without file content or OOB callback",
        vuln_type="xxe",
        source_tool="*",
        description="XXE detection without /etc/passwd content, OOB callback, or entity expansion proof",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "root:"},
            {"field": "evidence", "operator": "not_contains", "value": "callback"},
            {"field": "evidence", "operator": "not_contains", "value": "oob"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="XXE without file disclosure or OOB proof — parser may have entities disabled",
    ),

    # ── Cookie security FPs ────────────────────────────────

    FPPattern(
        id="FP-COOKIE-001",
        name="Missing Secure flag on localhost/dev cookie",
        vuln_type="cookie_security",
        source_tool="*",
        description="Missing Secure flag on cookie for localhost/development endpoint — expected",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(?i)(localhost|127\.0\.0\.1|\.local|\.dev|\.test)"},
            {"field": "title", "operator": "regex", "value": r"(?i)secure.*flag|cookie.*secure"},
        ],
        action="dismiss",
        confidence_penalty=-40,
        reason="Secure flag not required for localhost/development domains",
    ),
    FPPattern(
        id="FP-COOKIE-002",
        name="SameSite warning on non-auth cookie",
        vuln_type="cookie_security",
        source_tool="*",
        description="SameSite attribute missing on analytics/tracking cookies (not session cookies)",
        match_rules=[
            {"field": "evidence", "operator": "regex",
             "value": r"(?i)(ga_|_gid|_fbp|_gcl|utm_|__utm|analytics|tracking|NID|consent|preference)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="SameSite missing on tracking/analytics cookie — no security impact",
    ),

    # ── Rate limiting FPs ──────────────────────────────────

    FPPattern(
        id="FP-RATE-001",
        name="Rate limit missing on non-sensitive endpoint",
        vuln_type="rate_limiting",
        source_tool="*",
        description="Rate limiting absence on public read-only endpoint is informational",
        match_rules=[
            {"field": "url", "operator": "regex",
             "value": r"(?i)/(api/)?(health|status|version|docs|swagger|openapi|robots\.txt|sitemap)"},
        ],
        action="dismiss",
        confidence_penalty=-30,
        reason="Rate limiting on public health/docs endpoints is not security-critical",
    ),

    # ── Open redirect FPs ──────────────────────────────────

    FPPattern(
        id="FP-REDIR-004",
        name="Open redirect with protocol-relative URL (//)",
        vuln_type="open_redirect",
        source_tool="*",
        description="Protocol-relative redirect (//) is often handled safely by most apps",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)//[a-zA-Z0-9]+\.[a-zA-Z]{2,}"},
            {"field": "evidence", "operator": "not_contains", "value": "location:"},
        ],
        action="flag",
        confidence_penalty=-10,
        reason="Protocol-relative URL reflected but no Location header redirect confirmed",
    ),

    # ── Commix/command injection FPs ───────────────────────

    FPPattern(
        id="FP-CMDI-003",
        name="Commix time-based detection with network jitter",
        vuln_type="command_injection",
        source_tool="commix",
        description="Time-based command injection may be affected by network latency",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)time.*based|sleep|delay"},
            {"field": "evidence", "operator": "not_regex", "value": r"(?i)(uid=|root:|whoami|id=\d)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Time-based detection alone may be network latency — needs output-based confirmation",
    ),

    # ── Mass assignment FPs ────────────────────────────────

    FPPattern(
        id="FP-MASSASSIGN-001",
        name="Mass assignment on read-only fields",
        vuln_type="mass_assignment",
        source_tool="*",
        description="Extra fields sent in POST/PUT but server ignored them (no state change)",
        match_rules=[
            {"field": "evidence", "operator": "regex",
             "value": r"(?i)(field.*ignored|no.*change|same.*response|unchanged)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Server appears to ignore extra fields — mass assignment not confirmed",
    ),

    # ── SQL injection deep probe FPs ──────────────────────

    FPPattern(
        id="FP-SQLI-DEEP-001",
        name="SQLi probe status-only diff (no error/data leak)",
        vuln_type="sql_injection",
        source_tool="brain_analysis",
        description="Deep probe detected status code change but no SQL error or data extraction",
        match_rules=[
            {"field": "finding_type", "operator": "equals", "value": "hypothesis"},
            {"field": "evidence", "operator": "not_regex", "value": r"(?i)(syntax.*error|mysql|postgresql|oracle|mssql|sqlite|sql.*error)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Status-only SQL injection signal without error messages or data — likely FP",
    ),

    # ── Nuclei INFO/LOW noise ──────────────────────────────

    FPPattern(
        id="FP-NUCLEI-INFO-001",
        name="Nuclei INFO-level finding (informational only)",
        vuln_type="*",
        source_tool="nuclei",
        description="Nuclei INFO severity findings are informational, not vulnerabilities",
        match_rules=[
            {"field": "severity", "operator": "equals", "value": "info"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="INFO-severity finding is informational — not an exploitable vulnerability",
    ),

    # ── HTTP smuggling FPs ─────────────────────────────────

    FPPattern(
        id="FP-SMUGGLE-001",
        name="HTTP smuggling probe response ambiguity",
        vuln_type="http_smuggling",
        source_tool="*",
        description="HTTP smuggling detection based on ambiguous timeout/response behavior",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)(timeout|ambiguous|potential|might be)"},
            {"field": "evidence", "operator": "not_contains", "value": "confirmed"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Ambiguous smuggling signal — needs desync confirmation with multiple requests",
    ),

    # ── BOLA/BFLA FPs ─────────────────────────────────────

    FPPattern(
        id="FP-BOLA-001",
        name="BOLA test on public resource",
        vuln_type="bola",
        source_tool="*",
        description="Object-level access tested but resource is publicly accessible by design",
        match_rules=[
            {"field": "evidence", "operator": "regex",
             "value": r"(?i)(public.*resource|same.*response.*both|no.*auth.*required)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Resource accessible without auth by design — not a broken authorization issue",
    ),

    # ── Deep probe generic FPs ─────────────────────────────

    FPPattern(
        id="FP-DEEP-001",
        name="Deep probe finding with sub-threshold confidence",
        vuln_type="*",
        source_tool="brain_analysis",
        description="Deep probe result where session confidence never exceeded verification threshold",
        match_rules=[
            {"field": "tags", "operator": "contains", "value": "deep_probe"},
            {"field": "confidence_score", "operator": "regex", "value": r"^[0-3][0-9](\.\d+)?$"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Deep probe confidence too low — finding not adequately verified",
    ),

    # ── Subdomain takeover FPs (expanded) ──────────────────

    FPPattern(
        id="FP-TAKEOVER-002",
        name="Subdomain takeover CNAME to major provider",
        vuln_type="subdomain_takeover",
        source_tool="*",
        description="CNAME to AWS/Azure/GCP but bucket/resource may simply be misconfigured (not claimable)",
        match_rules=[
            {"field": "evidence", "operator": "regex",
             "value": r"(?i)(s3\.amazonaws|blob\.core\.windows|storage\.googleapis)"},
            {"field": "evidence", "operator": "not_contains", "value": "NoSuchBucket"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Cloud provider CNAME without confirmed claimability — may be active bucket",
    ),

    # ── XSS stored FPs ────────────────────────────────────

    FPPattern(
        id="FP-XSS-STORED-001",
        name="Stored XSS without rendered execution proof",
        vuln_type="xss",
        source_tool="*",
        description="Payload stored but not proven to execute in another user's browser context",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)stored.*xss"},
            {"field": "evidence", "operator": "not_regex",
             "value": r"(?i)(alert\(|document\.(cookie|domain)|onload=|onerror=)"},
        ],
        action="flag",
        confidence_penalty=-10,
        reason="Stored XSS claim without rendered execution evidence — may be encoded on output",
    ),

    # ── CORS same-org FP ──────────────────────────────────

    FPPattern(
        id="FP-CORS-004",
        name="CORS allows subdomain of same organization",
        vuln_type="cors_misconfiguration",
        source_tool="*",
        description="CORS allows requests from subdomains of the same organization",
        match_rules=[
            {"field": "evidence", "operator": "regex",
             "value": r"(?i)(subdomain|same[-_]?org|internal.*origin)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="CORS allowing same-org subdomains is often intentional — not a misconfiguration",
    ),

    # ── CSP report-only FP ─────────────────────────────────

    FPPattern(
        id="FP-CSP-001",
        name="CSP in report-only mode (not enforcing)",
        vuln_type="*",
        source_tool="*",
        description="Content-Security-Policy-Report-Only header detected — policy not enforced",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)csp|content.security.policy"},
            {"field": "header", "operator": "contains", "value": "content-security-policy-report-only"},
        ],
        action="flag",
        confidence_penalty=-10,
        reason="CSP is in report-only mode — monitoring, not blocking",
    ),

    # ── WPScan informational FPs ───────────────────────────

    FPPattern(
        id="FP-WPSCAN-001",
        name="WPScan WordPress version enumeration",
        vuln_type="*",
        source_tool="wpscan",
        description="WordPress version detected — informational unless known CVE applies",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)wordpress.*version|wp.*version"},
            {"field": "evidence", "operator": "not_contains", "value": "CVE"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="WordPress version detection is informational without specific CVE correlation",
    ),
    FPPattern(
        id="FP-WPSCAN-002",
        name="WPScan user enumeration via known API",
        vuln_type="*",
        source_tool="wpscan",
        description="WordPress user enumeration via wp-json/wp/v2/users is default WordPress behavior",
        match_rules=[
            {"field": "url", "operator": "contains", "value": "wp/v2/users"},
        ],
        action="flag",
        confidence_penalty=-10,
        reason="WordPress REST API user enumeration is default behavior — not always a vulnerability",
    ),

    # ── tplmap SSTI FPs ────────────────────────────────────

    FPPattern(
        id="FP-TPLMAP-001",
        name="Tplmap false detection on URL-encoded reflection",
        vuln_type="ssti",
        source_tool="tplmap",
        description="Template syntax reflected but URL-encoded — not evaluated by template engine",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"%7[bB]%7[bB]|%24%7[bB]"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Template syntax is URL-encoded in response — not rendered/evaluated",
    ),

    # ── SQLMap FPs ─────────────────────────────────────────

    FPPattern(
        id="FP-SQLMAP-001",
        name="SQLMap boolean-blind on always-true page",
        vuln_type="sql_injection",
        source_tool="sqlmap",
        description="SQLMap boolean-blind detection on page that returns same content for all inputs",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)boolean.*blind"},
            {"field": "evidence", "operator": "not_contains", "value": "UNION"},
            {"field": "evidence", "operator": "not_contains", "value": "extracted"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Boolean-blind SQLi without data extraction — may be false positive on static page",
    ),

    # ── CSRF FPs ───────────────────────────────────────────

    FPPattern(
        id="FP-CSRF-001",
        name="CSRF on state-reading GET endpoint",
        vuln_type="csrf",
        source_tool="*",
        description="CSRF reported on GET endpoint that only reads data (no state change)",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)(GET|read.only|no.*state.*change)"},
            {"field": "title", "operator": "regex", "value": r"(?i)csrf"},
        ],
        action="dismiss",
        confidence_penalty=-35,
        reason="CSRF on GET/read-only endpoint has no security impact — no state mutation",
    ),
    FPPattern(
        id="FP-CSRF-002",
        name="CSRF on API endpoint requiring auth token",
        vuln_type="csrf",
        source_tool="*",
        description="CSRF reported on endpoint that requires Bearer token (not cookie-based auth)",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)(bearer|authorization.*token|api[_-]?key)"},
            {"field": "title", "operator": "regex", "value": r"(?i)csrf"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="Token-based auth is inherently CSRF-immune — browser doesn't auto-send tokens",
    ),

    # ── NoSQLi FPs ─────────────────────────────────────────

    FPPattern(
        id="FP-NOSQLI-001",
        name="NoSQL injection without DB error/data leak",
        vuln_type="nosql_injection",
        source_tool="*",
        description="NoSQL injection payload sent but no database error or data extraction in response",
        match_rules=[
            {"field": "evidence", "operator": "not_regex",
             "value": r"(?i)(mongo|uncaught|objectid|bson|document.*not.*found|json.*parse)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="NoSQL injection without database error signals — detection may be behavioral only",
    ),

    # ── Host header injection FPs ──────────────────────────

    FPPattern(
        id="FP-HOSTHEADER-001",
        name="Host header reflected but not in sensitive context",
        vuln_type="*",
        source_tool="*",
        description="Host header value reflected in response body but not in password reset or redirect",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)host.*header.*inject"},
            {"field": "evidence", "operator": "not_regex",
             "value": r"(?i)(password.*reset|forgot.*password|redirect|location:)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Host header reflection without sensitive context (reset link, redirect) is low impact",
    ),

    # ── Timing-based generic FPs ───────────────────────────

    FPPattern(
        id="FP-TIMING-001",
        name="Timing-based detection with small delta",
        vuln_type="*",
        source_tool="*",
        description="Time-based detection with response time difference < 3 seconds (network noise)",
        match_rules=[
            {"field": "evidence", "operator": "regex",
             "value": r"(?i)time.*based|sleep|delay|[0-2]\.\d+\s*s(ec)?"},
            {"field": "evidence", "operator": "not_regex", "value": r"(?i)(5\.0|[5-9]\d*\.?\d*\s*s|10\.\d+)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Timing delta under 3 seconds may be network jitter, not confirmed injection",
    ),

    # ── Duplicate finding from multiple tools ──────────────

    FPPattern(
        id="FP-NUCLEI-DUP-001",
        name="Nuclei finding already covered by specialized tool",
        vuln_type="*",
        source_tool="nuclei",
        description="Nuclei generic template reports finding that a specialized tool also tests",
        match_rules=[
            {"field": "title", "operator": "regex",
             "value": r"(?i)(cors|xss|sqli|ssrf|open.*redirect|crlf).*misconfigur"},
        ],
        action="flag",
        confidence_penalty=-5,
        reason="Nuclei generic detection — specialized tool result should take precedence",
    ),

    # ── SPA catch-all path-based false positives ───────────

    FPPattern(
        id="FP-SPA-001",
        name="Nikto path finding on SPA-style host (200 catch-all)",
        vuln_type="*",
        source_tool="nikto",
        description="Nikto reports 'interesting' paths that return 200 on SPA with catch-all routing",
        match_rules=[
            {"field": "title", "operator": "regex",
             "value": r"(?i)(interesting|found|retrieved|identified).*(path|file|director|page|endpoint)"},
            {"field": "evidence", "operator": "regex", "value": r"(?i)status.*200|HTTP/\d.*200"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="SPA catch-all routing returns 200 for any path — nikto path findings unreliable",
    ),
    FPPattern(
        id="FP-SPA-002",
        name="File/path discovery without content verification",
        vuln_type="*",
        source_tool="*",
        description="Scanner found a path returning 200 but no evidence of actual sensitive content",
        match_rules=[
            {"field": "title", "operator": "regex",
             "value": r"(?i)(exposed|found|detect).*(\.env|\.git|backup|config|admin|panel|phpinfo)"},
            {"field": "evidence", "operator": "not_regex",
             "value": r"(?i)(APP_KEY|DB_PASS|root:|admin.*password|phpinfo\(\)|HEAD.*refs|DOCUMENT_ROOT)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Path exists but no actual sensitive content extracted — likely SPA/generic 200 response",
    ),

    # ── Revolution v4.0 — GitLab scan root-cause patterns ──────

    FPPattern(
        id="FP-CICD-001",
        name="CI/CD checker finding with 404 status",
        vuln_type="cicd_exposure",
        source_tool="cicd_checker",
        description="CI/CD endpoint returned 404 — the endpoint does not exist",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)(status|HTTP)\s*[:.]*\s*(404|410|not.found)"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="404 means the CI/CD endpoint does not exist on this host",
    ),
    FPPattern(
        id="FP-CICD-002",
        name="CI/CD checker on CDN-fronted host",
        vuln_type="cicd_exposure",
        source_tool="cicd_checker",
        description="CI/CD exposure reported on a host behind CDN — CDN serves generic responses",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"(?i)(cloudflare|akamai|fastly|cf-ray|x-amz-cf)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="CDN-fronted hosts return generic 200/403 for non-existent paths, triggering CI/CD false positives",
    ),
    FPPattern(
        id="FP-BIZLOGIC-001",
        name="Business logic finding on SPA/static endpoint",
        vuln_type="*",
        source_tool="business_logic_checker",
        description="Business logic vulnerability reported on a SPA catch-all or static response",
        match_rules=[
            {"field": "url", "operator": "regex",
             "value": r"(?i)(_payload\.json|__nuxt|_next/data|react-root|app-root|__sveltekit|vite-plugin|\.html(\?|$)|\.json(\?|$))"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="SPA frameworks return catch-all responses for any POST/PUT — not a real business logic flaw",
    ),
    FPPattern(
        id="FP-BIZLOGIC-002",
        name="Business logic finding without transaction keywords",
        vuln_type="*",
        source_tool="business_logic_checker",
        description="Business logic finding where response lacks any transaction/cart/price indicators",
        match_rules=[
            {"field": "evidence", "operator": "not_regex",
             "value": r"(?i)(total|price|amount|cart|order|balance|quantity|subtotal|payment|invoice)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Response contains no commerce/transaction content — likely a generic API or SPA response",
    ),
    FPPattern(
        id="FP-TECHCVE-001",
        name="Tech CVE with short technology name",
        vuln_type="outdated_software",
        source_tool="tech_cve_checker",
        description="CVE finding matched on a technology name shorter than 3 characters",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)CVE-\d{4}-\d+.*\b[a-z]{1,2}\b"},
            {"field": "evidence", "operator": "not_contains", "value": "version"},
        ],
        action="flag",
        confidence_penalty=-30,
        reason="Short tech names produce substring false matches (e.g. 'go' matching 'google')",
    ),
    FPPattern(
        id="FP-TECHCVE-002",
        name="Tech CVE without detected version",
        vuln_type="outdated_software",
        source_tool="tech_cve_checker",
        description="CVE finding without a confirmed technology version — cannot verify applicability",
        match_rules=[
            {"field": "evidence", "operator": "not_regex", "value": r"(?i)version\s*[:=]?\s*[\d]+\.[\d]+"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="Without a detected version number, CVE applicability cannot be confirmed",
    ),
    FPPattern(
        id="FP-TECHCVE-003",
        name="Old CVE without version confirmation",
        vuln_type="outdated_software",
        source_tool="tech_cve_checker",
        description="CVE older than 5 years matched without version — extremely unlikely to still apply",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"CVE-(201[0-9]|200\d)-"},
            {"field": "evidence", "operator": "not_contains", "value": "version"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="CVEs from 2019 or earlier without version evidence are almost always false positives",
    ),
    FPPattern(
        id="FP-MASSASSIGN-003",
        name="Mass assignment on static asset",
        vuln_type="*",
        source_tool="mass_assignment_checker",
        description="Mass assignment finding on a URL serving static content (.js/.css/.svg/.html)",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(?i)\.(js|css|svg|html|htm|png|jpg|gif|woff2?|ttf|ico)\b"},
        ],
        action="flag",
        confidence_penalty=-30,
        reason="Static assets cannot process mass assignment — the finding comes from HTML form labels",
    ),
    FPPattern(
        id="FP-MASSASSIGN-002",
        name="Mass assignment with common attribute name",
        vuln_type="*",
        source_tool="mass_assignment_checker",
        description="Finding where reflected field is a common HTML/JS attribute (id, name, type, data, class)",
        match_rules=[
            {"field": "title", "operator": "regex", "value": r"(?i)\((id|name|type|data|class|value|label|title|text|href)\)"},
        ],
        action="flag",
        confidence_penalty=-20,
        reason="Common HTML attribute names appear in any web page — not evidence of mass assignment",
    ),
    FPPattern(
        id="FP-SOURCEMAP-001",
        name="Source map on marketing/docs subdomain",
        vuln_type="*",
        source_tool="js_analyzer",
        description="Source map finding on a non-application subdomain (docs, blog, www, marketing, about, help, support, status)",
        match_rules=[
            {"field": "url", "operator": "regex", "value": r"(?i)^https?://(docs|blog|www|marketing|about|help|support|status)\."},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Marketing/docs subdomains rarely contain sensitive application source code",
    ),
    FPPattern(
        id="FP-JSDOM-001",
        name="JS DOM XSS on third-party analytics/CDN script",
        vuln_type="*",
        source_tool="js_analyzer",
        description="DOM XSS source/sink detected in third-party analytics, CDN, or challenge script",
        match_rules=[
            {"field": "evidence", "operator": "regex",
             "value": r"(?i)(_cf_chl_opt|cloudflare|challenges\.cloudflare\.com|static\.cloudflareinsights\.com|googletagmanager|gtm\.js|google-analytics|analytics\.js|facebook\.net|connect\.facebook|hotjar|hubspot|segment\.com|cdn\.jsdelivr|unpkg\.com)"},
        ],
        action="flag",
        confidence_penalty=-30,
        reason="Third-party analytics/CDN scripts are not part of the target application",
    ),
    FPPattern(
        id="FP-JSDOM-002",
        name="JS DOM XSS on third-party JS URL",
        vuln_type="*",
        source_tool="js_analyzer",
        description="DOM XSS finding on a JavaScript file hosted on a third-party domain",
        match_rules=[
            {"field": "url", "operator": "regex",
             "value": r"(?i)/gtm\.js|/analytics\.js|googletagmanager\.com|google-analytics\.com|facebook\.net|hotjar\.com|cdn\.segment\.com|cdn\.jsdelivr\.net"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="JavaScript file is hosted on a third-party domain, not controlled by the target",
    ),
    FPPattern(
        id="FP-SUBTAKEOVER-001",
        name="Subdomain takeover with active service",
        vuln_type="subdomain_takeover",
        source_tool="subdomain_takeover_checker",
        description="Subdomain claimed as takeover-vulnerable but HTTP check returns valid content",
        match_rules=[
            {"field": "evidence", "operator": "not_contains", "value": "HTTP response confirms"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="CNAME pattern alone is insufficient — subdomain is actively serving content",
    ),
    # --- Phase 5.2a additions: remaining GitLab FP gaps ---
    FPPattern(
        id="FP-COMMIX-001",
        name="Commix finding with empty evidence",
        vuln_type="*",
        source_tool="commix",
        description="Commix reported command injection but provided no evidence of execution",
        match_rules=[
            {"field": "evidence", "operator": "regex", "value": r"^(\s*)$"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="Commix finding without execution evidence is likely a connection-level artifact",
    ),
    FPPattern(
        id="FP-SOURCEMAP-002",
        name="Source map in SPA build directory",
        vuln_type="*",
        source_tool="js_analyzer",
        description="Source map in a known SPA build directory (_nuxt, _next, static/js, build/static)",
        match_rules=[
            {"field": "url", "operator": "regex",
             "value": r"(?i)(/(_nuxt|_next|static/js|build/static|dist/assets)/.*\.map(\?|$))"},
            {"field": "title", "operator": "contains", "value": "source map"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="SPA build directories intentionally expose source maps; these are public build artifacts",
    ),
    FPPattern(
        id="FP-COOKIE-003",
        name="Cookie finding on staging/dev subdomain",
        vuln_type="security_misconfiguration",
        source_tool="cookie_checker",
        description="Cookie misconfiguration on a non-production subdomain (staging, dev, test, sandbox)",
        match_rules=[
            {"field": "url", "operator": "regex",
             "value": r"(?i)(staging|dev-|test-|sandbox|preprod|uat|qa-|stg-)"},
        ],
        action="flag",
        confidence_penalty=-15,
        reason="Staging/dev environments often have relaxed cookie settings by design",
    ),
    FPPattern(
        id="FP-SENSITIVE-URL-001",
        name="Sensitive URL is a public repo or docs link",
        vuln_type="*",
        source_tool="sensitive_url_finder",
        description="Sensitive URL finding that points to a public repository blob, docs page, or wiki",
        match_rules=[
            {"field": "url", "operator": "regex",
             "value": r"(?i)(/(-/)?blob/|/(-/)?tree/|/(-/)?wiki/|/(-/)?raw/|/docs/|readme\.md)"},
        ],
        action="flag",
        confidence_penalty=-30,
        reason="Public repository files and documentation are intentionally accessible",
    ),
    FPPattern(
        id="FP-SENSITIVE-URL-002",
        name="Sensitive URL with fuzz suffix in filename",
        vuln_type="*",
        source_tool="sensitive_url_finder",
        description="Sensitive file URL where the filename has random characters appended (fuzzer artifact)",
        match_rules=[
            {"field": "url", "operator": "regex",
             "value": r"(?i)(\.htaccess|\.env|\.git|\.svn|web\.config|\.DS_Store)[A-Za-z0-9]{4,}"},
        ],
        action="flag",
        confidence_penalty=-25,
        reason="Random suffix on sensitive filename indicates fuzzer artifact, not real file",
    ),
]

class KnownFPMatcher:
    """
    Bilinen FP kalıplarını bulgulara karşı eşleştiren motor.

    Usage:
        matcher = KnownFPMatcher()
        result = matcher.check(finding)
        if result["is_known_fp"]:
            print(f"Known FP: {result['pattern'].name}")
    """

    def __init__(self, extra_patterns: list[FPPattern] | None = None) -> None:
        self._patterns = list(KNOWN_FP_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def check(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Bir bulguyu tüm FP kalıplarına karşı kontrol et.

        Args:
            finding: Bulgu dict'i. Beklenen alanlar:
                vuln_type, url, status_code, response_body,
                evidence, title, tool/source_tool, headers

        Returns:
            {
                "is_known_fp": bool,
                "matches": [FPPattern, ...],
                "total_penalty": int,
                "action": "flag" | "dismiss" | "verify" | "clean",
                "reasons": [str, ...],
            }
        """
        vuln_type = finding.get("vuln_type", finding.get("vulnerability_type", finding.get("type", "unknown")))
        tool = finding.get("tool", finding.get("source_tool", ""))

        matches: list[FPPattern] = []
        total_penalty = 0
        reasons: list[str] = []

        for pattern in self._patterns:
            # Vuln type filtresi
            if pattern.vuln_type != "*" and pattern.vuln_type != vuln_type:
                continue

            # Tool filtresi
            if pattern.source_tool != "*" and pattern.source_tool != tool:
                continue

            # Kural eşleme
            if self._match_rules(pattern.match_rules, finding):
                matches.append(pattern)
                total_penalty += pattern.confidence_penalty
                reasons.append(pattern.reason)
                pattern.times_matched += 1

                logger.debug(
                    f"FP pattern matched | pattern={pattern.id} ({pattern.name}) | "
                    f"penalty={pattern.confidence_penalty}"
                )

        # En sert action'ı uygula
        action = "clean"
        if matches:
            action_priority = {"dismiss": 3, "verify": 2, "flag": 1}
            action = max(
                (m.action for m in matches),
                key=lambda a: action_priority.get(a, 0),
            )

        return {
            "is_known_fp": bool(matches),
            "matches": matches,
            "total_penalty": total_penalty,
            "action": action,
            "reasons": reasons,
        }

    def _match_rules(
        self, rules: list[dict[str, str]], finding: dict[str, Any]
    ) -> bool:
        """
        Tüm kuralların eşleşip eşleşmediğini kontrol et (AND logic).

        Her kural: {"field": ..., "operator": ..., "value": ...}
        """
        if not rules:
            return False

        for rule in rules:
            field = rule.get("field", "")
            operator = rule.get("operator", "contains")
            value = rule.get("value", "")

            # Field değerini al
            field_value = self._get_field_value(finding, field)

            if not self._eval_rule(field_value, operator, value):
                return False  # AND — bir kural tutmazsa eşleşme yok

        return True

    @staticmethod
    def _get_field_value(finding: dict[str, Any], field: str) -> str:
        """Bulgudan belirtilen alan değerini al."""
        if field == "response_body":
            return str(finding.get("response_body", finding.get("response", "")))
        elif field == "status_code":
            return str(finding.get("status_code", ""))
        elif field == "url":
            return str(finding.get("url", finding.get("endpoint", "")))
        elif field == "header":
            headers = finding.get("headers", finding.get("response_headers", {}))
            if isinstance(headers, dict):
                return "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
            return str(headers).lower()
        elif field == "title":
            return str(finding.get("title", finding.get("name", "")))
        elif field == "evidence":
            return str(finding.get("evidence", ""))
        else:
            val = finding.get(field, "")
            if isinstance(val, list):
                return " ".join(str(v) for v in val)
            return str(val)

    @staticmethod
    def _eval_rule(field_value: str, operator: str, pattern: str) -> bool:
        """Tek bir kuralı değerlendir."""
        fv = field_value.lower()

        if operator == "contains":
            return pattern.lower() in fv
        elif operator == "not_contains":
            return pattern.lower() not in fv
        elif operator == "equals":
            return fv == pattern.lower()
        elif operator == "regex":
            try:
                return bool(re.search(pattern, fv, re.IGNORECASE))
            except re.error:
                return False
        elif operator == "not_regex":
            try:
                return not bool(re.search(pattern, fv, re.IGNORECASE))
            except re.error:
                return True

        return False

    def add_pattern(self, pattern: FPPattern) -> None:
        """Yeni FP kalıbı ekle."""
        self._patterns.append(pattern)
        logger.info(f"New FP pattern added: {pattern.id} — {pattern.name}")

    def get_statistics(self) -> dict[str, int]:
        """Kalıp eşleme istatistikleri."""
        stats: dict[str, int] = {}
        for p in self._patterns:
            if p.times_matched > 0:
                stats[p.id] = p.times_matched
        return stats

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)


__all__ = [
    "KnownFPMatcher",
    "FPPattern",
    "KNOWN_FP_PATTERNS",
]
