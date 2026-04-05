"""
WhiteHatHacker AI — Analysis Phase Prompts

Zafiyet analizi, saldırı yüzeyi değerlendirmesi ve derinlemesine
teknik analiz için brain modeline verilecek promptlar.
Primary Brain (BaronLLM v2 /think) tarafından kullanılır — derin analiz,
yüksek doğruluk.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# System Prompts
# ============================================================

ANALYSIS_SYSTEM_PROMPT = """\
You are an elite cybersecurity analyst performing deep vulnerability
analysis. Your analysis must be thorough, precise, and actionable.

RULES:
- Consider all attack vectors and their interactions
- Evaluate WAF/CDN interference in all assessments
- Always calculate proper CVSS v3.1 scores with justification
- Chain vulnerabilities when possible for maximum impact
- Consider business context and real-world exploitability
- Return structured JSON responses
"""

ATTACK_SURFACE_SYSTEM = """\
You are mapping the complete attack surface of the target.
Think systematically about every entry point, every parameter,
every service that could be exploited. Consider both obvious
and subtle attack vectors.
"""

CORRELATION_SYSTEM = """\
You are a vulnerability correlation expert. Your job is to find
connections between individual findings that could form attack
chains with amplified impact. Look for patterns that individual
scanners would miss.
"""


# ============================================================
# Task Prompt Builders
# ============================================================

def build_vulnerability_analysis_prompt(
    vuln_type: str,
    target_url: str,
    parameter: str = "",
    payload: str = "",
    response_code: int = 0,
    response_body: str = "",
    headers: dict[str, str] | None = None,
    tool_name: str = "",
    waf_detected: str = "",
    tech_stack: list[str] | None = None,
) -> str:
    """Tek bir zafiyet bulgusunun derinlemesine analizi."""
    headers_text = ""
    if headers:
        headers_text = "\n".join(f"    {k}: {v}" for k, v in headers.items())

    tech_text = ", ".join(tech_stack) if tech_stack else "unknown"
    response_preview = response_body[:2000] if response_body else "N/A"

    return f"""\
## Task: Deep Vulnerability Analysis

Perform thorough analysis of the following vulnerability finding.
Determine if it's genuine, assess exploitability, and calculate
accurate CVSS score.

### Finding Details
- **Type:** {vuln_type}
- **Target:** {target_url}
- **Parameter:** {parameter or "N/A"}
- **Payload Used:** {payload or "N/A"}
- **Detected By:** {tool_name or "N/A"}
- **WAF/CDN:** {waf_detected or "none detected"}
- **Tech Stack:** {tech_text}

### HTTP Response
- **Status Code:** {response_code or "N/A"}
- **Headers:**
{headers_text or "    Not available"}
- **Body (preview):**
```
{response_preview}
```

### Analysis Requirements
1. Is this a TRUE vulnerability or FALSE POSITIVE?
2. What is the root cause?
3. What is the maximum impact if exploited?
4. Can this be chained with other vulnerability types?
5. What are the exploitation prerequisites?

### Required JSON Response
```json
{{
  "verdict": "true_positive|false_positive|needs_verification",
  "confidence": 0-100,
  "root_cause": "technical explanation of the vulnerability",
  "cvss": {{
    "score": 7.5,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "justification": "why this score"
  }},
  "exploitability": {{
    "is_exploitable": true,
    "complexity": "low|medium|high",
    "prerequisites": ["what attacker needs"],
    "real_world_impact": "what damage can be done"
  }},
  "chain_potential": [
    {{"chain_with": "vuln_type", "amplified_impact": "description"}}
  ],
  "waf_bypass_needed": false,
  "remediation": "specific fix recommendation",
  "false_positive_indicators": ["reasons it might be FP"],
  "true_positive_indicators": ["reasons it's real"]
}}
```

### Calibration Examples

**Example 1 (TRUE POSITIVE — SQLi):**
Type: SQL Injection, Target: /api/users?id=1, Payload: `1 UNION SELECT null,version()--`, Response 200, body contains "PostgreSQL 14.2".
→ {{"verdict": "true_positive", "confidence": 95, "root_cause": "User input in id parameter directly concatenated into SQL query without parameterization", "cvss": {{"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "justification": "Network-accessible, no auth required, data extraction confirmed"}}, "exploitability": {{"is_exploitable": true, "complexity": "low", "prerequisites": [], "real_world_impact": "Full database read access — user PII, credentials, business data"}}, "chain_potential": [{{"chain_with": "SSRF", "amplified_impact": "SQLi data + internal network pivot"}}], "waf_bypass_needed": false, "remediation": "Use parameterized queries/prepared statements for all SQL operations. Apply allowlist validation on id parameter.", "false_positive_indicators": [], "true_positive_indicators": ["PostgreSQL version string in response body", "UNION SELECT executed successfully"]}}

**Example 2 (FALSE POSITIVE — WAF block):**
Type: XSS, Target: /search?q=test, Payload: `<script>alert(1)</script>`, Response 403, body contains "Cloudflare" and "cf-ray" header.
→ {{"verdict": "false_positive", "confidence": 90, "root_cause": "WAF blocked the request before it reached the application", "cvss": {{"score": 0.0, "vector": "", "justification": "No vulnerability — WAF block"}}, "exploitability": {{"is_exploitable": false, "complexity": "high", "prerequisites": ["WAF bypass"], "real_world_impact": "None — payload was blocked"}}, "chain_potential": [], "waf_bypass_needed": true, "remediation": "No action needed — WAF is functioning correctly", "false_positive_indicators": ["403 status code", "Cloudflare challenge page", "cf-ray header"], "true_positive_indicators": []}}
"""


def build_attack_surface_analysis_prompt(
    target: str,
    endpoints: list[dict[str, Any]],
    services: list[dict[str, Any]],
    technologies: list[str],
    known_vulns: list[str] | None = None,
) -> str:
    """Saldırı yüzeyi haritalama analizi."""
    endpoints_text = "\n".join(
        f"  - {e.get('url', '?')} | params: {e.get('parameters', [])} "
        f"| method: {e.get('method', 'GET')}"
        for e in endpoints[:60]
    )
    services_text = "\n".join(
        f"  - {s.get('port', '?')}/{s.get('protocol', 'tcp')} "
        f"— {s.get('service', '?')} {s.get('version', '')}"
        for s in services[:30]
    )
    vulns_text = "\n".join(
        f"  - {v}" for v in (known_vulns or [])[:20]
    )

    return f"""\
## Task: Attack Surface Mapping

Build complete attack surface map for **{target}** and prioritize
attack vectors by potential impact and likelihood of success.

### Endpoints ({len(endpoints)} total)
{endpoints_text}

### Services
{services_text}

### Technology Stack
{", ".join(technologies) or "unknown"}

### Known Vulnerabilities So Far
{vulns_text or "  None identified yet"}

### Required JSON Response
```json
{{
  "attack_surface_score": 0-100,
  "entry_points": [
    {{
      "type": "web_endpoint|api|service|network",
      "target": "url or host:port",
      "attack_vectors": ["sqli", "xss", "ssrf"],
      "priority": 1-10,
      "estimated_difficulty": "low|medium|high",
      "potential_impact": "critical|high|medium|low"
    }}
  ],
  "high_value_targets": [
    {{
      "target": "description",
      "reason": "why valuable",
      "recommended_approach": "how to test"
    }}
  ],
  "blind_spots": ["areas that need more recon"],
  "attack_strategy": {{
    "phase1": "quick wins to try first",
    "phase2": "deeper testing",
    "phase3": "advanced/chained attacks"
  }}
}}
```
"""


def build_finding_correlation_prompt(
    findings: list[dict[str, Any]],
    target: str,
) -> str:
    """Birden fazla bulguyu korelatif analiz et."""
    findings_text = "\n".join(
        f"  {i+1}. [{f.get('severity', '?')}] {f.get('type', '?')} "
        f"at {f.get('endpoint', '?')} (found by {f.get('tool', '?')})"
        for i, f in enumerate(findings[:30])
    )

    return f"""\
## Task: Finding Correlation & Attack Chain Discovery

Analyze all findings for **{target}** together and identify:
1. Duplicate or overlapping findings
2. Findings that can be chained for higher impact
3. Patterns indicating systemic issues
4. Missing tests based on found vulnerabilities

### Current Findings ({len(findings)} total)
{findings_text}

### Required JSON Response
```json
{{
  "duplicates": [
    {{"finding_ids": [1, 5], "reason": "same vuln different tools"}}
  ],
  "attack_chains": [
    {{
      "name": "Chain Name",
      "steps": [
        {{"finding_id": 1, "role": "entry point"}},
        {{"finding_id": 3, "role": "privilege escalation"}}
      ],
      "combined_impact": "critical",
      "combined_cvss": 9.8,
      "narrative": "attacker can..."
    }}
  ],
  "systemic_issues": [
    {{"pattern": "no input validation", "affected_endpoints": 5}}
  ],
  "missing_tests": [
    {{"based_on_finding": 2, "suggested_test": "try SSRF from SQLi"}}
  ],
  "consolidated_risk": "critical|high|medium|low"
}}
```
"""


def build_threat_model_prompt(
    target: str,
    architecture: str = "",
    data_types: list[str] | None = None,
    user_roles: list[str] | None = None,
    external_integrations: list[str] | None = None,
) -> str:
    """STRIDE tabanlı tehdit modelleme."""
    data_text = ", ".join(data_types) if data_types else "unknown"
    roles_text = ", ".join(user_roles) if user_roles else "unknown"
    integrations_text = "\n".join(
        f"  - {i}" for i in (external_integrations or [])
    )

    return f"""\
## Task: STRIDE Threat Modeling

Perform STRIDE-based threat modeling for **{target}**.

### Architecture
{architecture or "Web application (details unknown)"}

### Data Types Handled
{data_text}

### User Roles
{roles_text}

### External Integrations
{integrations_text or "  Unknown"}

### Required JSON Response
```json
{{
  "threats": [
    {{
      "stride_category": "S|T|R|I|D|E",
      "threat": "description",
      "affected_component": "component name",
      "likelihood": "low|medium|high",
      "impact": "low|medium|high|critical",
      "risk_score": 0-25,
      "mitigations": ["recommended controls"],
      "test_methods": ["how to verify this threat"]
    }}
  ],
  "highest_risks": ["top 3 risk summaries"],
  "trust_boundaries": ["identified trust boundaries"],
  "data_flow_concerns": ["data handling issues"],
  "overall_threat_level": "low|medium|high|critical"
}}
```
"""


def build_impact_assessment_prompt(
    vuln_type: str,
    target: str,
    severity: str,
    exploitable_data: str = "",
    user_base: str = "",
    business_context: str = "",
) -> str:
    """İş etkisi değerlendirmesi."""
    return f"""\
## Task: Business Impact Assessment

Assess the real-world business impact of a **{severity}** severity
**{vuln_type}** vulnerability on **{target}**.

### Context
- **Exploitable Data:** {exploitable_data or "Unknown"}
- **User Base:** {user_base or "Unknown"}
- **Business Context:** {business_context or "Unknown"}

### Required JSON Response
```json
{{
  "impact_dimensions": {{
    "confidentiality": {{
      "rating": "none|low|medium|high|critical",
      "details": "what data could be exposed"
    }},
    "integrity": {{
      "rating": "none|low|medium|high|critical",
      "details": "what could be modified"
    }},
    "availability": {{
      "rating": "none|low|medium|high|critical",
      "details": "service disruption potential"
    }}
  }},
  "business_impact": {{
    "financial": "estimated financial impact or range",
    "reputational": "reputation damage assessment",
    "regulatory": "GDPR/PCI-DSS/HIPAA implications",
    "operational": "business operation impact"
  }},
  "affected_users": "estimate of affected users/customers",
  "worst_case_scenario": "description of worst possible outcome",
  "urgency": "immediate|within_24h|within_week|low_priority"
}}
```
"""


__all__ = [
    "ANALYSIS_SYSTEM_PROMPT",
    "ATTACK_SURFACE_SYSTEM",
    "CORRELATION_SYSTEM",
    "build_vulnerability_analysis_prompt",
    "build_attack_surface_analysis_prompt",
    "build_finding_correlation_prompt",
    "build_threat_model_prompt",
    "build_impact_assessment_prompt",
]
