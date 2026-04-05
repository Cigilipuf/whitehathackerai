"""
WhiteHatHacker AI — Reconnaissance Phase Prompts

Keşif aşamasında brain modeline verilecek sistem ve görev promptları.
Secondary Brain (BaronLLM v2 /no_think) tarafından kullanılır — hızlı karar,
düşük latency.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# System Prompts
# ============================================================

RECON_SYSTEM_PROMPT = """\
You are an expert bug bounty hunter in the reconnaissance phase.
Your job: analyze gathered intelligence about the target and decide
next actions.

RULES:
- NEVER go out of scope
- Prioritize every discovery by potential security impact
- Focus on clues that expand the attack surface
- Always return structured JSON responses
- Think like a professional penetration tester
"""

PASSIVE_RECON_SYSTEM = """\
You are performing PASSIVE reconnaissance. You must NOT send any
requests to the target directly. Analyze data from public sources:
certificate transparency logs, DNS records, OSINT databases,
internet archives, code repositories.

Return your analysis as structured JSON.
"""

ACTIVE_RECON_SYSTEM = """\
You are performing ACTIVE reconnaissance. You may send requests
to in-scope targets while respecting rate limits.

Focus on: alive hosts, open ports, running services, technology
stack, web application structure.

Return your analysis as structured JSON.
"""


# ============================================================
# Task Prompt Builders
# ============================================================

def build_scope_analysis_prompt(
    targets: list[str],
    program_rules: str = "",
    in_scope: list[str] | None = None,
    out_of_scope: list[str] | None = None,
) -> str:
    """Scope analizi için prompt oluştur."""
    in_scope_text = "\n".join(f"  - {s}" for s in (in_scope or []))
    out_scope_text = "\n".join(f"  - {s}" for s in (out_of_scope or []))
    targets_text = "\n".join(f"  - {t}" for t in targets)

    return f"""\
## Task: Scope Analysis

Analyze the following bug bounty program scope and determine:
1. Which targets are valid for testing
2. What types of testing are allowed
3. Recommended scan strategy (stealth / balanced / aggressive)
4. Risk assessment for the engagement

### Targets
{targets_text}

### Program Rules
{program_rules or "No specific rules provided"}

### In-Scope
{in_scope_text or "  - Not explicitly defined"}

### Out-of-Scope
{out_scope_text or "  - Not explicitly defined"}

### Required JSON Response
```json
{{
  "valid_targets": ["list of confirmed in-scope targets"],
  "excluded_targets": ["targets to skip and why"],
  "testing_types_allowed": ["web", "api", "network", ...],
  "recommended_profile": "stealth|balanced|aggressive",
  "risk_level": "low|medium|high",
  "warnings": ["any concerns or ambiguities"],
  "strategy_notes": "brief scan strategy recommendation"
}}
```

### Calibration Example

**Example:**
Targets: ["*.example.com"], Program: "Web applications only. No physical/social engineering. Do not test login.example.com", In-scope: ["*.example.com"], Out-of-scope: ["login.example.com"].
→ {{"valid_targets": ["*.example.com"], "excluded_targets": ["login.example.com — explicitly excluded by program rules"], "testing_types_allowed": ["web", "api"], "recommended_profile": "balanced", "risk_level": "low", "warnings": ["Wildcard scope — confirm subdomains are owned by target before testing"], "strategy_notes": "Start with subdomain enumeration, then web crawling and common vuln scanning. Avoid login.example.com."}}
"""


def build_subdomain_analysis_prompt(
    domain: str,
    subdomains: list[str],
    resolved: dict[str, str] | None = None,
) -> str:
    """Subdomain keşif sonuçlarını analiz et."""
    sub_text = "\n".join(f"  - {s}" for s in subdomains[:100])
    resolved_text = ""
    if resolved:
        resolved_text = "\n".join(
            f"  - {k} → {v}" for k, v in list(resolved.items())[:50]
        )

    return f"""\
## Task: Subdomain Analysis

Analyze discovered subdomains for **{domain}** and identify:
1. High-value targets (admin panels, staging, APIs, etc.)
2. Potential subdomain takeover candidates
3. Infrastructure patterns (cloud providers, CDN usage)
4. Recommended next steps

### Discovered Subdomains ({len(subdomains)} total)
{sub_text}
{"..." if len(subdomains) > 100 else ""}

### DNS Resolution
{resolved_text or "  Not yet resolved"}

### Required JSON Response
```json
{{
  "high_value_targets": [
    {{"subdomain": "admin.example.com", "reason": "admin panel", "priority": 1}}
  ],
  "takeover_candidates": [
    {{"subdomain": "old.example.com", "indicator": "NXDOMAIN/CNAME to unclaimed"}}
  ],
  "infrastructure": {{
    "cloud_providers": ["AWS", "Cloudflare"],
    "cdn_usage": true,
    "shared_hosting": false
  }},
  "patterns": ["description of naming patterns noticed"],
  "next_steps": ["recommended actions"]
}}
```
"""


def build_port_scan_analysis_prompt(
    target: str,
    open_ports: list[dict[str, Any]],
) -> str:
    """Port tarama sonuçlarını analiz et."""
    ports_text = "\n".join(
        f"  - {p.get('port', '?')}/{p.get('protocol', 'tcp')} "
        f"— {p.get('service', 'unknown')} {p.get('version', '')}"
        for p in open_ports[:50]
    )

    return f"""\
## Task: Port Scan Analysis

Analyze open ports and services on **{target}** to identify:
1. Potentially vulnerable services
2. Attack vectors per service
3. Priority order for further testing
4. Known CVEs based on service versions

### Open Ports ({len(open_ports)} found)
{ports_text}

### Required JSON Response
```json
{{
  "service_analysis": [
    {{
      "port": 443,
      "service": "nginx/1.18.0",
      "risk_level": "medium",
      "attack_vectors": ["web app testing", "SSL/TLS checks"],
      "known_cves": ["CVE-XXXX-YYYY"],
      "notes": "..."
    }}
  ],
  "high_risk_services": [8080, 6379],
  "testing_priority": [443, 8080, 22, 3306],
  "overall_exposure": "low|medium|high|critical",
  "recommendations": ["immediate actions"]
}}
```
"""


def build_tech_detection_analysis_prompt(
    target: str,
    technologies: list[dict[str, Any]],
    headers: dict[str, str] | None = None,
) -> str:
    """Teknoloji tespiti sonuçlarını analiz et."""
    tech_text = "\n".join(
        f"  - {t.get('name', '?')} {t.get('version', '')} "
        f"(category: {t.get('category', 'unknown')})"
        for t in technologies
    )
    headers_text = ""
    if headers:
        headers_text = "\n".join(f"  {k}: {v}" for k, v in headers.items())

    return f"""\
## Task: Technology Stack Analysis

Analyze the technology stack detected on **{target}**:
1. Identify known vulnerabilities per technology/version
2. Default credential risks
3. Misconfig opportunities
4. Recommended testing approach per technology

### Detected Technologies
{tech_text}

### HTTP Headers
{headers_text or "  Not available"}

### Required JSON Response
```json
{{
  "tech_vulns": [
    {{
      "technology": "WordPress 6.1",
      "known_issues": ["plugin vulns", "xmlrpc enabled"],
      "specific_tests": ["wpscan", "nuclei wordpress templates"],
      "risk_level": "medium"
    }}
  ],
  "default_creds_risk": [
    {{"service": "phpmyadmin", "check": "root/empty password"}}
  ],
  "security_headers_missing": ["CSP", "X-Frame-Options"],
  "waf_detected": "cloudflare|akamai|none",
  "overall_tech_risk": "low|medium|high"
}}
```
"""


def build_osint_analysis_prompt(
    target: str,
    emails: list[str] | None = None,
    social_accounts: list[str] | None = None,
    leaked_data: list[str] | None = None,
    github_findings: list[str] | None = None,
    google_dorks_results: list[str] | None = None,
) -> str:
    """OSINT sonuçlarını analiz et."""
    sections = []
    if emails:
        sections.append("### Discovered Emails\n" + "\n".join(f"  - {e}" for e in emails[:30]))
    if social_accounts:
        sections.append("### Social Accounts\n" + "\n".join(f"  - {s}" for s in social_accounts[:20]))
    if leaked_data:
        sections.append("### Potential Data Leaks\n" + "\n".join(f"  - {l}" for l in leaked_data[:20]))
    if github_findings:
        sections.append("### GitHub Findings\n" + "\n".join(f"  - {g}" for g in github_findings[:20]))
    if google_dorks_results:
        sections.append("### Google Dork Results\n" + "\n".join(f"  - {g}" for g in google_dorks_results[:20]))

    all_sections = "\n\n".join(sections) if sections else "No OSINT data collected yet."

    return f"""\
## Task: OSINT Analysis

Analyze OSINT data for **{target}** and determine:
1. Credential exposure risk
2. Sensitive information leaks
3. Social engineering attack vectors
4. Code/config leak implications

{all_sections}

### Required JSON Response
```json
{{
  "credential_risk": "none|low|medium|high|critical",
  "sensitive_leaks": [
    {{"type": "api_key", "source": "github", "severity": "high"}}
  ],
  "email_patterns": "format used (e.g., first.last@domain.com)",
  "social_engineering_risk": "low|medium|high",
  "actionable_findings": [
    {{"finding": "description", "next_step": "what to do"}}
  ],
  "priority_alerts": ["immediate concerns"]
}}
```
"""


def build_web_crawl_analysis_prompt(
    target: str,
    urls: list[str],
    forms: list[dict[str, Any]] | None = None,
    js_files: list[str] | None = None,
    api_endpoints: list[str] | None = None,
) -> str:
    """Web crawl sonuçlarını analiz et."""
    urls_text = "\n".join(f"  - {u}" for u in urls[:80])
    forms_text = ""
    if forms:
        forms_text = "\n".join(
            f"  - {f.get('action', '?')} method={f.get('method', '?')} "
            f"params={f.get('params', [])}"
            for f in forms[:20]
        )
    js_text = "\n".join(f"  - {j}" for j in (js_files or [])[:30])
    api_text = "\n".join(f"  - {a}" for a in (api_endpoints or [])[:30])

    return f"""\
## Task: Web Crawl Analysis

Analyze crawl results for **{target}** and identify:
1. Interesting endpoints for vulnerability testing
2. Parameter injection points
3. Authentication/authorization boundaries
4. Hidden or undocumented functionality

### Discovered URLs ({len(urls)} total)
{urls_text}

### Forms
{forms_text or "  None discovered"}

### JavaScript Files
{js_text or "  None discovered"}

### API Endpoints
{api_text or "  None discovered"}

### Required JSON Response
```json
{{
  "interesting_endpoints": [
    {{"url": "/admin/settings", "reason": "admin panel", "test_type": "auth_bypass"}}
  ],
  "injection_points": [
    {{"url": "/search", "param": "q", "type": "possible_xss"}}
  ],
  "auth_boundaries": {{
    "login_url": "/login",
    "authenticated_areas": ["/dashboard", "/api/v1"],
    "session_mechanism": "cookie|jwt|bearer"
  }},
  "hidden_functionality": [
    {{"url": "/debug", "indicator": "debug endpoint exposed"}}
  ],
  "js_secrets": [
    {{"file": "/js/app.js", "finding": "API key in source"}}
  ],
  "test_priority": [
    {{"endpoint": "/api/v1/users", "tests": ["idor", "auth_bypass"]}}
  ]
}}
```
"""


def build_recon_summary_prompt(
    target: str,
    subdomains_count: int = 0,
    live_hosts: int = 0,
    open_ports_count: int = 0,
    technologies: list[str] | None = None,
    urls_discovered: int = 0,
    key_findings: list[str] | None = None,
) -> str:
    """Keşif özeti ve sonraki adım önerisi."""
    findings_text = "\n".join(
        f"  {i+1}. {f}" for i, f in enumerate(key_findings or [])
    )
    tech_text = ", ".join(technologies or ["unknown"])

    return f"""\
## Task: Reconnaissance Summary & Next Steps

Provide a comprehensive summary of the recon phase for **{target}**
and recommend the optimal attack strategy.

### Reconnaissance Statistics
- Subdomains discovered: {subdomains_count}
- Live hosts: {live_hosts}
- Open ports: {open_ports_count}
- URLs discovered: {urls_discovered}
- Technologies: {tech_text}

### Key Findings So Far
{findings_text or "  No significant findings yet"}

### Required JSON Response
```json
{{
  "overall_assessment": "brief summary of attack surface",
  "risk_rating": "low|medium|high|critical",
  "top_targets": [
    {{"target": "host:port", "reason": "why it's interesting", "priority": 1}}
  ],
  "recommended_scan_types": [
    {{"type": "sql_injection", "targets": ["url1"], "priority": "high"}},
    {{"type": "xss", "targets": ["url2"], "priority": "medium"}}
  ],
  "recommended_tools": ["tool1", "tool2"],
  "estimated_test_time": "hours",
  "missing_recon": ["areas not yet covered"]
}}
```
"""


__all__ = [
    "RECON_SYSTEM_PROMPT",
    "PASSIVE_RECON_SYSTEM",
    "ACTIVE_RECON_SYSTEM",
    "build_scope_analysis_prompt",
    "build_subdomain_analysis_prompt",
    "build_port_scan_analysis_prompt",
    "build_tech_detection_analysis_prompt",
    "build_osint_analysis_prompt",
    "build_web_crawl_analysis_prompt",
    "build_recon_summary_prompt",
]
