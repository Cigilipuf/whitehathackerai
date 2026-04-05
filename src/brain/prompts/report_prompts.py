"""
WhiteHatHacker AI — Report Writing Prompts

Profesyonel bug bounty raporu yazmak için brain modeline verilecek
promptlar. Primary Brain (BaronLLM v2 /think) tarafından kullanılır —
ikna edici, net, teknik rapor yazımı.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# System Prompts
# ============================================================

REPORT_SYSTEM_PROMPT = """\
You are an experienced bug bounty hunter writing a professional
vulnerability report. Your reports must be:

1. CLEAR — A triager should understand the issue in 30 seconds
2. TECHNICAL — Include all technical details needed to reproduce
3. PERSUASIVE — Clearly demonstrate real-world impact
4. ACTIONABLE — Include specific remediation steps
5. WELL-STRUCTURED — Follow platform-specific formatting

Write in English. Use professional tone. Be concise but thorough.
"""

EXECUTIVE_SUMMARY_SYSTEM = """\
You are writing an executive summary of security findings for
non-technical stakeholders. Use business language, focus on
risk and impact, avoid technical jargon.
"""


# ============================================================
# Task Prompt Builders
# ============================================================

def build_report_title_prompt(
    vuln_type: str,
    target: str,
    impact: str = "",
    component: str = "",
) -> str:
    """Rapor başlığı oluştur."""
    return f"""\
## Task: Generate Report Title

Create a concise, impactful report title for a bug bounty submission.

### Details
- **Vulnerability Type:** {vuln_type}
- **Target:** {target}
- **Component:** {component or "main application"}
- **Impact:** {impact or "unknown"}

### Requirements
- Max 80 characters
- Include vulnerability type
- Include affected component
- Convey severity/impact
- Professional tone

### Good Examples
- "Stored XSS in User Profile Bio Leads to Account Takeover"
- "Blind SQL Injection in /api/search Exposes User Database"
- "SSRF via Image URL Parameter Allows Internal Network Access"
- "IDOR in /api/v1/invoices/{id} Exposes Other Users' Financial Data"

### Required JSON Response
```json
{{
  "title": "main title",
  "alternatives": ["alt title 1", "alt title 2"]
}}
```
"""


def build_report_summary_prompt(
    vuln_type: str,
    target: str,
    impact: str,
    severity: str,
    cvss_score: float = 0.0,
) -> str:
    """Rapor özeti oluştur."""
    return f"""\
## Task: Write Vulnerability Summary

Write a 2-3 sentence summary that captures the essence of the
vulnerability for the report introduction.

### Details
- **Type:** {vuln_type}
- **Target:** {target}
- **Impact:** {impact}
- **Severity:** {severity} (CVSS: {cvss_score})

### Requirements
- 2-3 sentences maximum
- Explain what the vulnerability is
- Where it exists
- What an attacker can achieve
- Why it matters

### Required JSON Response
```json
{{
  "summary": "The complete summary text",
  "one_liner": "Single sentence version for quick reference"
}}
```
"""


def build_report_impact_prompt(
    vuln_type: str,
    target: str,
    severity: str,
    data_exposed: str = "",
    user_count_affected: str = "",
    business_functions: list[str] | None = None,
) -> str:
    """Detaylı etki analizi yaz."""
    functions_text = ", ".join(business_functions) if business_functions else "unknown"

    return f"""\
## Task: Write Impact Analysis

Write a compelling, accurate impact analysis section for the report.
This section convinces the triager of the vulnerability's severity.

### Details
- **Vulnerability:** {vuln_type}
- **Target:** {target}
- **Severity:** {severity}
- **Data Exposed:** {data_exposed or "to be determined"}
- **Users Affected:** {user_count_affected or "unknown"}
- **Business Functions:** {functions_text}

### Requirements
- Start with worst-case realistic scenario
- Include both technical and business impact
- Mention regulatory implications if applicable (GDPR, PCI-DSS)
- Be specific, not generic
- Use concrete examples

### Required JSON Response
```json
{{
  "impact_text": "Full impact analysis paragraph(s)",
  "bullet_points": [
    "An attacker could...",
    "This could lead to...",
    "Affected data includes..."
  ],
  "regulatory_concerns": ["GDPR Article X", "PCI-DSS Req Y"],
  "worst_case": "Description of worst realistic scenario"
}}
```
"""


def build_report_reproduction_prompt(
    vuln_type: str,
    target_url: str,
    parameter: str = "",
    payload: str = "",
    http_requests: list[dict[str, Any]] | None = None,
    screenshots: list[str] | None = None,
    prerequisites: list[str] | None = None,
) -> str:
    """Yeniden üretim (reproduction) adımları yaz."""
    prereq_text = "\n".join(
        f"  - {p}" for p in (prerequisites or ["No special prerequisites"])
    )

    requests_text = ""
    if http_requests:
        for i, req in enumerate(http_requests[:5], 1):
            requests_text += f"\n### Request {i}\n"
            requests_text += f"```http\n{req.get('method', 'GET')} {req.get('url', '?')} HTTP/1.1\n"
            for hk, hv in req.get('headers', {}).items():
                requests_text += f"{hk}: {hv}\n"
            if req.get('body'):
                requests_text += f"\n{req['body']}"
            requests_text += "\n```\n"
            if req.get('response_status'):
                requests_text += f"Response: {req['response_status']}\n"

    return f"""\
## Task: Write Reproduction Steps

Write clear, detailed step-by-step reproduction instructions that
any security engineer can follow to verify the vulnerability.

### Vulnerability
- **Type:** {vuln_type}
- **Target:** {target_url}
- **Parameter:** {parameter or "N/A"}
- **Payload:** `{payload or "N/A"}`

### Prerequisites
{prereq_text}

### HTTP Request/Response Data
{requests_text or "Not available"}

### Requirements
- Numbered steps, starting from a clean browser/state
- Include exact URLs, parameters, and values
- Show what to look for after each step
- Include both manual and automated reproduction methods
- Reference screenshots where applicable

### Required JSON Response
```json
{{
  "steps": [
    {{
      "number": 1,
      "action": "Navigate to https://target.com/login",
      "details": "Use any browser",
      "tip": "optional helpful tip"
    }}
  ],
  "automated_command": "curl/python command for quick verification",
  "expected_result": "what proves the vulnerability",
  "notes": "any important considerations"
}}
```
"""


def build_report_remediation_prompt(
    vuln_type: str,
    tech_stack: list[str] | None = None,
    current_defense: str = "",
) -> str:
    """Düzeltme önerisi yaz."""
    tech_text = ", ".join(tech_stack) if tech_stack else "unknown"

    return f"""\
## Task: Write Remediation Recommendations

Write specific, actionable remediation steps for the vulnerability.

### Details
- **Vulnerability Type:** {vuln_type}
- **Technology Stack:** {tech_text}
- **Current Defense:** {current_defense or "No specific defense observed"}

### Requirements
- Primary fix (root cause)
- Secondary controls (defense in depth)
- Quick temporary fix if the full fix takes time
- Include code examples where possible
- Reference OWASP/CWE best practices

### Required JSON Response
```json
{{
  "primary_fix": {{
    "description": "Root cause fix",
    "code_example": "sample fix code",
    "effort": "low|medium|high"
  }},
  "secondary_controls": [
    {{
      "control": "WAF rule",
      "description": "Add specific WAF rule",
      "effort": "low"
    }}
  ],
  "quick_fix": {{
    "description": "Temporary mitigation",
    "implementation": "how to implement quickly"
  }},
  "references": [
    {{"source": "OWASP", "url": "https://...", "title": "..."}}
  ],
  "testing_after_fix": "how to verify the fix works"
}}
```

### Calibration Example

**Example (SQLi remediation):**
Type: SQL Injection, Tech: [Python, Flask, PostgreSQL], Current Defense: none.
→ {{"primary_fix": {{"description": "Use parameterized queries with SQLAlchemy ORM or psycopg2 placeholders instead of string concatenation", "code_example": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))", "effort": "medium"}}, "secondary_controls": [{{"control": "Input validation", "description": "Validate id parameter is numeric using int() cast", "effort": "low"}}, {{"control": "WAF rule", "description": "Block SQL keywords in request parameters", "effort": "low"}}], "quick_fix": {{"description": "Add input type validation to reject non-numeric id values", "implementation": "Add: if not user_id.isdigit(): return 400"}}, "references": [{{"source": "OWASP", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "title": "SQL Injection Prevention Cheat Sheet"}}], "testing_after_fix": "Retry original SQLi payload — should return 400 or sanitized query result without database error"}}
"""


def build_full_report_prompt(
    vuln_type: str,
    target: str,
    severity: str,
    cvss_score: float,
    cvss_vector: str,
    impact: str,
    reproduction_steps: list[str],
    evidence: str = "",
    remediation: str = "",
    platform: str = "hackerone",
) -> str:
    """Tam rapor oluştur — tek seferde."""
    steps_text = "\n".join(
        f"  {i+1}. {s}" for i, s in enumerate(reproduction_steps)
    )

    return f"""\
## Task: Write Complete Bug Bounty Report

Write a full, professional bug bounty report ready for submission
to **{platform}**.

### Vulnerability Details
- **Type:** {vuln_type}
- **Target:** {target}
- **Severity:** {severity} (CVSS: {cvss_score})
- **CVSS Vector:** {cvss_vector}
- **Impact:** {impact}

### Reproduction Steps
{steps_text}

### Evidence
{evidence or "Screenshots and HTTP logs attached"}

### Remediation Notes
{remediation or "To be written"}

### Required Output
Write the complete report in Markdown format following the
{platform} template structure. Include:
1. Title
2. Summary (2-3 sentences)
3. Severity justification with CVSS breakdown
4. Detailed reproduction steps
5. Impact analysis
6. Remediation recommendation
7. References (CWE, OWASP)

Return the complete report as a single markdown string in JSON:
```json
{{
  "report_markdown": "# Title\\n\\n## Summary\\n...",
  "title": "extracted title",
  "severity": "{severity}",
  "cwe_ids": ["CWE-XXX"],
  "quality_score": 0-100
}}
```
"""


def build_executive_summary_prompt(
    target: str,
    total_findings: int,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    info: int = 0,
    top_findings: list[str] | None = None,
    scan_duration: str = "",
) -> str:
    """Yönetici özeti oluştur."""
    findings_text = "\n".join(
        f"  - {f}" for f in (top_findings or [])[:10]
    )

    return f"""\
## Task: Write Executive Summary

Write an executive summary for the complete security assessment
of **{target}** suitable for non-technical stakeholders.

### Statistics
- Total Findings: {total_findings}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}
- Informational: {info}
- Scan Duration: {scan_duration or "N/A"}

### Top Findings
{findings_text or "  No critical findings"}

### Requirements
- 1 page maximum
- Business language, minimize jargon
- Clear risk assessment
- Prioritized action items
- Overall security posture assessment

### Required JSON Response
```json
{{
  "executive_summary": "Full executive summary text",
  "risk_rating": "critical|high|medium|low",
  "key_recommendations": [
    "Fix critical SQL injection immediately",
    "Implement input validation framework"
  ],
  "security_posture": "description of overall security state"
}}
```
"""


REPORT_SELF_ASSESS_SYSTEM = """\
You are a senior bug bounty triager reviewing a submitted report.
Evaluate the report for completeness, clarity, accuracy, and
persuasiveness. Be constructive but honest about gaps.
"""


def build_report_self_assess_prompt(report_markdown: str) -> str:
    """Build a prompt for the brain to critique a generated report."""
    # Truncate very long reports to fit context window
    truncated = report_markdown[:12000]
    return f"""\
## Task: Review Bug Bounty Report Quality

Read the following bug bounty report and assess its quality.
Identify specific issues and suggest concrete improvements.

### Report
```markdown
{truncated}
```

### Evaluate These Dimensions (score each 1-10)
1. **Clarity** — Can a triager understand the issue in 30 seconds?
2. **Reproduction** — Are steps complete and unambiguous?
3. **Impact** — Is business impact convincingly explained?
4. **Evidence** — Are PoC, HTTP exchanges, screenshots present?
5. **Remediation** — Are fix suggestions specific and actionable?

### Required JSON Response
```json
{{
  "overall_score": 0-100,
  "dimensions": {{
    "clarity": {{"score": 1-10, "issue": "..." }},
    "reproduction": {{"score": 1-10, "issue": "..." }},
    "impact": {{"score": 1-10, "issue": "..." }},
    "evidence": {{"score": 1-10, "issue": "..." }},
    "remediation": {{"score": 1-10, "issue": "..." }}
  }},
  "missing_sections": ["list of missing or empty sections"],
  "improvements": [
    "specific actionable improvement 1",
    "specific actionable improvement 2"
  ],
  "verdict": "ready_to_submit | needs_improvement | major_gaps"
}}
```
"""


__all__ = [
    "REPORT_SYSTEM_PROMPT",
    "EXECUTIVE_SUMMARY_SYSTEM",
    "REPORT_SELF_ASSESS_SYSTEM",
    "build_report_title_prompt",
    "build_report_summary_prompt",
    "build_report_impact_prompt",
    "build_report_reproduction_prompt",
    "build_report_remediation_prompt",
    "build_full_report_prompt",
    "build_executive_summary_prompt",
    "build_report_self_assess_prompt",
]
