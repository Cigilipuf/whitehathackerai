"""
WhiteHatHacker AI — Bugcrowd Report Template

Bugcrowd platformuna uyumlu rapor formatı.
Bugcrowd'un VRT (Vulnerability Rating Taxonomy) entegrasyonu.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# Bugcrowd VRT (Vulnerability Rating Taxonomy) Mapping
# ============================================================

VRT_MAPPING = {
    "sql_injection": {
        "category": "Server-Side Injection",
        "subcategory": "SQL Injection",
        "priority": "P1",
        "vrt_id": "server_side_injection.sql_injection",
    },
    "command_injection": {
        "category": "Server-Side Injection",
        "subcategory": "Command Injection",
        "priority": "P1",
        "vrt_id": "server_side_injection.command_injection",
    },
    "xss_reflected": {
        "category": "Cross-Site Scripting (XSS)",
        "subcategory": "Reflected",
        "priority": "P2",
        "vrt_id": "cross_site_scripting_xss.reflected",
    },
    "xss_stored": {
        "category": "Cross-Site Scripting (XSS)",
        "subcategory": "Stored",
        "priority": "P2",
        "vrt_id": "cross_site_scripting_xss.stored",
    },
    "xss_dom": {
        "category": "Cross-Site Scripting (XSS)",
        "subcategory": "DOM-Based",
        "priority": "P2",
        "vrt_id": "cross_site_scripting_xss.dom_based",
    },
    "ssrf": {
        "category": "Server-Side Request Forgery (SSRF)",
        "subcategory": "Internal SSRF",
        "priority": "P2",
        "vrt_id": "server_side_request_forgery.internal",
    },
    "ssti": {
        "category": "Server-Side Injection",
        "subcategory": "Template Injection",
        "priority": "P1",
        "vrt_id": "server_side_injection.template_injection",
    },
    "idor": {
        "category": "Broken Access Control",
        "subcategory": "IDOR",
        "priority": "P2",
        "vrt_id": "broken_access_control.idor",
    },
    "authentication_bypass": {
        "category": "Broken Authentication",
        "subcategory": "Authentication Bypass",
        "priority": "P1",
        "vrt_id": "broken_authentication.auth_bypass",
    },
    "cors_misconfiguration": {
        "category": "Server Security Misconfiguration",
        "subcategory": "CORS Misconfiguration",
        "priority": "P3",
        "vrt_id": "server_security_misconfiguration.cors",
    },
    "open_redirect": {
        "category": "Unvalidated Redirects and Forwards",
        "subcategory": "Open Redirect",
        "priority": "P4",
        "vrt_id": "unvalidated_redirects_and_forwards.open_redirect",
    },
    "local_file_inclusion": {
        "category": "Server-Side Injection",
        "subcategory": "File Inclusion",
        "priority": "P1",
        "vrt_id": "server_side_injection.file_inclusion.local",
    },
    "information_disclosure": {
        "category": "Sensitive Data Exposure",
        "subcategory": "Information Disclosure",
        "priority": "P4",
        "vrt_id": "sensitive_data_exposure.information_disclosure",
    },
    "race_condition": {
        "category": "Application-Level Denial of Service",
        "subcategory": "Race Condition",
        "priority": "P3",
        "vrt_id": "race_condition",
    },
    "ssl_tls_misconfiguration": {
        "category": "Server Security Misconfiguration",
        "subcategory": "TLS/SSL",
        "priority": "P4",
        "vrt_id": "server_security_misconfiguration.tls_ssl",
    },
    "rate_limit_bypass": {
        "category": "Broken Access Control",
        "subcategory": "Rate Limiting",
        "priority": "P4",
        "vrt_id": "broken_access_control.rate_limiting",
    },
    "business_logic": {
        "category": "Broken Access Control",
        "subcategory": "Business Logic",
        "priority": "P3",
        "vrt_id": "broken_access_control.business_logic",
    },
}

# Bugcrowd priority to severity label
PRIORITY_LABELS = {
    "P1": "Critical",
    "P2": "Severe",
    "P3": "Moderate",
    "P4": "Low",
    "P5": "Informational",
}


class BugcrowdTemplate:
    """
    Bugcrowd platformuna uyumlu rapor oluşturucu.

    VRT taxonomy + Bugcrowd'un rapor formatı standartlarına uyar.
    """

    @staticmethod
    def format_finding(finding: Any) -> str:
        """
        Tek bir bulguyu Bugcrowd Markdown formatında oluştur.

        Bugcrowd format:
        Title → URL → VRT → Description → Steps → Impact → PoC → Fix
        """
        lines: list[str] = []

        vrt = VRT_MAPPING.get(finding.vulnerability_type, {
            "category": "Other",
            "subcategory": "Unclassified",
            "priority": "P3",
            "vrt_id": "other",
        })

        priority_label = PRIORITY_LABELS.get(vrt["priority"], "Unknown")

        # ── Title ─────────────────────────────────────────────
        lines.append(f"## {finding.title}")
        lines.append("")

        # ── Metadata Table ────────────────────────────────────
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **URL** | `{finding.endpoint}` |")
        lines.append(f"| **VRT Category** | {vrt['category']} > {vrt['subcategory']} |")
        lines.append(f"| **VRT ID** | `{vrt['vrt_id']}` |")
        lines.append(f"| **Priority** | {vrt['priority']} — {priority_label} |")
        lines.append(f"| **CVSS** | {finding.cvss_score} |")
        if finding.cwe_ids:
            lines.append(f"| **CWE** | {', '.join(finding.cwe_ids)} |")
        if finding.parameter:
            lines.append(f"| **Parameter** | `{finding.parameter}` |")
        lines.append("")

        # ── Description ──────────────────────────────────────
        lines.append("### Description")
        if finding.summary:
            lines.append(finding.summary)
        else:
            lines.append(
                f"A {(finding.vulnerability_type or 'unknown').replace('_', ' ')} vulnerability "
                f"was discovered at `{finding.endpoint}`. "
                f"This issue allows an attacker to "
                f"{_vuln_action(finding.vulnerability_type)}."
            )
        lines.append("")

        # ── Steps to Reproduce ────────────────────────────────
        lines.append("### Steps to Reproduce")
        if finding.steps_to_reproduce:
            for i, step in enumerate(finding.steps_to_reproduce, 1):
                lines.append(f"{i}. {step}")
        else:
            step_num = 1
            lines.append(f"{step_num}. Go to `{finding.endpoint or finding.target}`")
            step_num += 1
            if finding.parameter:
                lines.append(f"{step_num}. Locate the `{finding.parameter}` parameter")
                step_num += 1
            if finding.payload:
                lines.append(f"{step_num}. Submit the following payload: `{finding.payload}`")
                step_num += 1
            lines.append(f"{step_num}. Observe the vulnerability in the response")
        lines.append("")

        # ── Proof of Concept ─────────────────────────────────
        lines.append("### Proof of Concept")

        if finding.http_request:
            lines.append("\n**Request:**")
            lines.append(f"```http\n{finding.http_request[:4000]}\n```")

        if finding.http_response:
            resp = finding.http_response
            if len(resp) > 2000:
                resp = resp[:2000] + "\n[... truncated ...]"
            lines.append("\n**Response:**")
            lines.append(f"```http\n{resp}\n```")

        if finding.poc_code and finding.poc_code != finding.payload:
            lines.append("\n**PoC Script:**")
            lines.append(f"```python\n{finding.poc_code[:3000]}\n```")

        for ss in getattr(finding, "screenshots", []):
            lines.append(f"\n![Evidence]({ss})")

        lines.append("")

        # ── Impact ────────────────────────────────────────────
        lines.append("### Impact")
        if finding.impact:
            lines.append(finding.impact)
        else:
            from src.reporting.templates.hackerone_template import _default_impact
            lines.append(_default_impact(finding.vulnerability_type))
        lines.append("")

        # ── Remediation ──────────────────────────────────────
        if finding.remediation:
            lines.append("### Recommended Fix")
            lines.append(finding.remediation)
            lines.append("")

        # ── References ────────────────────────────────────────
        if finding.references:
            lines.append("### References")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def to_api_payload(
        finding: Any,
        program_id: str = "",
        target_id: str = "",
    ) -> dict[str, Any]:
        """
        Bugcrowd API submission payload oluştur.

        Returns:
            Bugcrowd API'ye gönderilebilecek dict
        """
        vrt = VRT_MAPPING.get(finding.vulnerability_type, {
            "vrt_id": "other",
            "priority": "P3",
        })

        markdown_body = BugcrowdTemplate.format_finding(finding)

        payload = {
            "submission": {
                "title": finding.title,
                "description": markdown_body,
                "severity": int(vrt["priority"].replace("P", "")),
                "vrt_id": vrt["vrt_id"],
                "vrt_version": "latest",
                "extra_info": {
                    "endpoint": finding.endpoint,
                    "parameter": finding.parameter,
                    "cvss_score": finding.cvss_score,
                    "cvss_vector": finding.cvss_vector,
                },
            },
        }

        if program_id:
            payload["submission"]["program_id"] = program_id

        if target_id:
            payload["submission"]["target_id"] = target_id

        if finding.http_request or finding.http_response:
            payload["submission"]["http_traffic"] = {
                "request": finding.http_request[:5000] if finding.http_request else "",
                "response": finding.http_response[:5000] if finding.http_response else "",
            }

        return payload

    @staticmethod
    def format_full_report(report: Any) -> str:
        """
        Birden fazla bulgu içeren tam Bugcrowd raporu oluştur.
        """
        lines: list[str] = []

        lines.append(f"# Bugcrowd Submission: {report.target}")
        lines.append(
            f"\n**Program:** {report.program_name or 'N/A'}"
        )
        lines.append(
            f"**Date:** {__import__('time').strftime('%Y-%m-%d', __import__('time').gmtime(report.generated_at))}"
        )
        lines.append(f"**Total Findings:** {report.finding_count}")

        # Priority breakdown
        priorities: dict[str, int] = {}
        for f in report.findings:
            vrt = VRT_MAPPING.get(f.vulnerability_type, {"priority": "P3"})
            p = vrt["priority"]
            priorities[p] = priorities.get(p, 0) + 1

        lines.append("\n### Priority Breakdown")
        for p in sorted(priorities.keys()):
            label = PRIORITY_LABELS.get(p, "Unknown")
            lines.append(f"- **{p} ({label}):** {priorities[p]}")

        lines.append(f"\n{'='*60}\n")

        for i, finding in enumerate(report.findings, 1):
            lines.append(f"# Submission {i}\n")
            lines.append(BugcrowdTemplate.format_finding(finding))
            lines.append(f"\n{'='*60}\n")

        return "\n".join(lines)


def _vuln_action(vuln_type: str) -> str:
    """Zafiyet türüne göre saldırgan eylemi."""
    ACTIONS = {
        "sql_injection": "extract or manipulate database contents",
        "command_injection": "execute arbitrary OS commands on the server",
        "xss_reflected": "execute malicious JavaScript in a victim's browser",
        "xss_stored": "persistently execute malicious JavaScript for any visiting user",
        "xss_dom": "manipulate the DOM to execute arbitrary JavaScript",
        "ssrf": "perform server-side requests to internal resources",
        "ssti": "execute arbitrary code on the server via template injection",
        "idor": "access or modify other users' resources",
        "authentication_bypass": "bypass authentication and gain unauthorized access",
        "cors_misconfiguration": "steal sensitive data via cross-origin requests",
        "open_redirect": "redirect users to malicious websites",
        "local_file_inclusion": "read sensitive files from the server",
        "information_disclosure": "access sensitive internal information",
        "race_condition": "exploit timing vulnerabilities for unauthorized actions",
    }
    return ACTIONS.get(vuln_type, "perform unauthorized actions")


__all__ = [
    "BugcrowdTemplate",
    "VRT_MAPPING",
    "PRIORITY_LABELS",
]
