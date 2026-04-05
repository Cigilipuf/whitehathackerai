"""
WhiteHatHacker AI — FP Elimination Brain Prompts

Specialized prompts for false positive elimination analysis.
Uses Primary Brain (BaronLLM v2) for deep analysis.
All prompts in English for optimal performance.
"""

from __future__ import annotations

from src.tools.base import Finding


def build_fp_analysis_prompt(finding: Finding) -> str:
    """
    Build a detailed prompt for false positive analysis.

    Args:
        finding: The finding to analyze

    Returns:
        Prompt string
    """
    sections = [
        "# Vulnerability Finding — False Positive Analysis",
        "",
        "## Finding Details",
        f"- **Title:** {finding.title}",
        f"- **Type:** {finding.vulnerability_type}",
        f"- **Severity:** {finding.severity}",
        f"- **Tool:** {finding.tool_name}",
        f"- **Target:** {finding.target}",
        f"- **Endpoint:** {finding.endpoint}",
        f"- **Parameter:** {finding.parameter}",
    ]

    if finding.payload:
        sections.extend([
            "",
            "## Payload Used",
            "```",
            f"{finding.payload}",
            "```",
        ])

    if finding.http_request:
        sections.extend([
            "",
            "## HTTP Request",
            "```http",
            f"{finding.http_request[:2000]}",
            "```",
        ])

    if finding.http_response:
        sections.extend([
            "",
            "## HTTP Response",
            "```http",
            f"{finding.http_response[:3000]}",
            "```",
        ])

    if finding.evidence:
        sections.extend([
            "",
            "## Evidence",
            "```",
            f"{finding.evidence[:2000]}",
            "```",
        ])

    if finding.description:
        sections.extend([
            "",
            "## Description",
            f"{finding.description}",
        ])

    sections.extend([
        "",
        "## Calibration Examples",
        "",
        "**Example 1 (TRUE POSITIVE):**",
        "XSS detected in `q=` parameter. Payload `<script>alert(1)</script>` reflected",
        "unencoded in response body within `<div>` context. Response status 200,",
        "Content-Type: text/html. No encoding or sanitization applied.",
        '→ {"verdict": "real", "confidence": 92, "reasoning": "Payload reflected without any encoding in HTML body context. Script tags intact — trivially exploitable reflected XSS."}',
        "",
        "**Example 2 (FALSE POSITIVE):**",
        "XSS detected in `search=` parameter. Payload reflected but HTML-entity encoded:",
        "`&lt;script&gt;alert(1)&lt;/script&gt;`. Response Content-Type: text/html.",
        "X-XSS-Protection: 1; mode=block header present.",
        '→ {"verdict": "false_positive", "confidence": 88, "reasoning": "Server properly HTML-encodes special characters. Script tags are neutralized. XSS-Protection header also active."}',
        "",
        "**Example 3 (FALSE POSITIVE — WAF artifact):**",
        "SQL injection detected. Payload `1 OR 1=1` returned 403 Forbidden with",
        "Cloudflare challenge page. cf-ray header present. Response body contains",
        "'Attention Required!' and CAPTCHA.",
        '→ {"verdict": "false_positive", "confidence": 95, "reasoning": "403 response is a Cloudflare WAF block, not a SQL error. The WAF detected the injection attempt and blocked it. No evidence of actual SQL execution."}',
        "",
        "## Task",
        "Analyze the finding above and determine:",
        "1. Is this finding a REAL vulnerability or a FALSE POSITIVE?",
        "2. Was the payload actually executed/reflected?",
        "3. Is there WAF/CDN/Load Balancer interference?",
        "4. Does the response context support the vulnerability?",
        "5. Was encoding or sanitization applied?",
        "",
        "Respond in JSON format:",
        '{"verdict": "real" or "false_positive", "confidence": 0-100, '
        '"reasoning": "detailed justification"}',
    ])

    return "\n".join(sections)


def build_severity_assessment_prompt(finding: Finding) -> str:
    """CVSS scoring and severity assessment prompt."""
    return f"""# CVSS v3.1 Severity Assessment

## Vulnerability
- **Type:** {finding.vulnerability_type}
- **Title:** {finding.title}
- **Target:** {finding.target}
- **Endpoint:** {finding.endpoint}

## Description
{finding.description}

## Task
Calculate the CVSS v3.1 score for this vulnerability. Justify each metric.

Respond in JSON format:
{{
    "cvss_score": 0.0-10.0,
    "cvss_vector": "CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?",
    "severity": "critical|high|medium|low|info",
    "impact_description": "Business impact description",
    "reasoning": "Justification for each metric"
}}"""


def build_fp_exploit_strategy_prompt(finding: Finding) -> str:
    """Exploit strategy and PoC generation prompt (FP verification context)."""
    return f"""# Exploit Strategy and PoC Generation

## Verified Vulnerability
- **Type:** {finding.vulnerability_type}
- **Target:** {finding.target}
- **Endpoint:** {finding.endpoint}
- **Parameter:** {finding.parameter}
- **Payload:** {finding.payload}

## Task
1. Create a SAFE Proof of Concept (PoC) for this vulnerability
2. The PoC should only prove the vulnerability exists
3. NEVER cause real damage, steal data, or hijack accounts
4. Use minimum effective exploit

Respond in JSON format:
{{
    "poc_type": "curl_command|python_script|browser_steps",
    "poc_code": "PoC code or commands",
    "steps": ["Step 1", "Step 2", ...],
    "expected_result": "Expected outcome",
    "safety_notes": "Safety notes"
}}"""


__all__ = [
    "build_fp_analysis_prompt",
    "build_severity_assessment_prompt",
    "build_fp_exploit_strategy_prompt",
]
