"""
WhiteHatHacker AI — HackerOne Report Template

HackerOne platformuna uyumlu, profesyonel rapor formatı.
API submission desteği ile birlikte kullanılır.
"""

from __future__ import annotations

from typing import Any



# HackerOne severity mapping
SEVERITY_RATINGS = {
    "critical": {"rating": "critical", "label": "Critical"},
    "high": {"rating": "high", "label": "High"},
    "medium": {"rating": "medium", "label": "Medium"},
    "low": {"rating": "low", "label": "Low"},
    "info": {"rating": "none", "label": "None"},
}

# HackerOne weakness taxonomy (common)
WEAKNESS_MAP = {
    "sql_injection": {"id": 67, "name": "SQL Injection"},
    "xss_reflected": {"id": 61, "name": "Cross-site Scripting (XSS) - Reflected"},
    "xss_stored": {"id": 62, "name": "Cross-site Scripting (XSS) - Stored"},
    "xss_dom": {"id": 63, "name": "Cross-site Scripting (XSS) - DOM"},
    "command_injection": {"id": 58, "name": "Command Injection - Generic"},
    "ssrf": {"id": 68, "name": "Server-Side Request Forgery (SSRF)"},
    "idor": {"id": 55, "name": "Insecure Direct Object Reference (IDOR)"},
    "ssti": {"id": 73, "name": "Server Side Template Injection"},
    "authentication_bypass": {"id": 27, "name": "Authentication Bypass Using an Alternate Path or Channel"},
    "cors_misconfiguration": {"id": 16, "name": "CORS Misconfiguration"},
    "open_redirect": {"id": 53, "name": "Open Redirect"},
    "local_file_inclusion": {"id": 70, "name": "Path Traversal"},
    "information_disclosure": {"id": 18, "name": "Information Disclosure"},
    "race_condition": {"id": 26, "name": "Time-of-check Time-of-use (TOCTOU) Race Condition"},
    "ssl_tls_misconfiguration": {"id": 166, "name": "Cryptographic Issues - Generic"},
}


class HackerOneTemplate:
    """
    HackerOne platformuna uyumlu rapor oluşturucu.

    Hem human-readable markdown hem de API submission için
    JSON formatında çıktı üretir.
    """

    @staticmethod
    def format_finding(finding: Any) -> str:
        """
        Tek bir bulguyu HackerOne Markdown formatında oluştur.

        HackerOne'ın beklediği standart rapor yapısını takip eder:
        Summary → Severity → Steps to Reproduce → Impact → PoC → Fix
        """
        lines: list[str] = []

        # ── Summary ───────────────────────────────────────────
        lines.append("## Summary")
        if finding.summary:
            lines.append(finding.summary)
        else:
            lines.append(
                f"A {(finding.vulnerability_type or 'unknown').replace('_', ' ')} vulnerability "
                f"was identified at `{finding.endpoint}`"
                f"{f' via the `{finding.parameter}` parameter' if finding.parameter else ''}."
            )
        lines.append("")

        # ── Severity ─────────────────────────────────────────
        lines.append("## Severity")
        sev = SEVERITY_RATINGS.get(getattr(finding.severity, "value", str(finding.severity or "medium")), SEVERITY_RATINGS["medium"])
        lines.append(f"**Rating:** {sev['label']}")
        lines.append(f"**CVSS Score:** {finding.cvss_score}")
        lines.append(f"**CVSS Vector:** `{finding.cvss_vector}`")
        lines.append("")

        # ── Steps to Reproduce ────────────────────────────────
        lines.append("## Steps to Reproduce")
        if finding.steps_to_reproduce:
            for i, step in enumerate(finding.steps_to_reproduce, 1):
                lines.append(f"{i}. {step}")
        else:
            # Auto-generate steps from technical details
            step_num = 1
            if finding.endpoint:
                lines.append(f"{step_num}. Navigate to `{finding.endpoint}`")
                step_num += 1
            if finding.parameter:
                lines.append(
                    f"{step_num}. Identify the `{finding.parameter}` parameter"
                )
                step_num += 1
            if finding.payload:
                lines.append(
                    f"{step_num}. Inject the following payload: `{finding.payload}`"
                )
                step_num += 1
            lines.append(
                f"{step_num}. Observe the vulnerability manifesting in the response"
            )
        lines.append("")

        # ── Supporting Material / PoC ─────────────────────────
        lines.append("## Supporting Material/References")

        if finding.http_request:
            lines.append("\n### HTTP Request")
            lines.append(f"```http\n{finding.http_request[:4000]}\n```")

        if finding.http_response:
            lines.append("\n### HTTP Response")
            # Truncate long responses
            resp = finding.http_response
            if len(resp) > 2000:
                resp = resp[:2000] + "\n... [truncated]"
            lines.append(f"```http\n{resp}\n```")

        if finding.poc_code:
            lines.append("\n### Proof of Concept")
            lines.append(f"```\n{finding.poc_code[:3000]}\n```")

        for ss in getattr(finding, "screenshots", []):
            lines.append(f"\n![Evidence Screenshot]({ss})")

        lines.append("")

        # ── Impact ────────────────────────────────────────────
        lines.append("## Impact")
        if finding.impact:
            lines.append(finding.impact)
        else:
            lines.append(
                _default_impact(finding.vulnerability_type)
            )
        lines.append("")

        # ── Suggested Fix ─────────────────────────────────────
        if finding.remediation:
            lines.append("## Suggested Remediation")
            lines.append(finding.remediation)
            lines.append("")

        # ── References ────────────────────────────────────────
        if finding.references or finding.cwe_ids:
            lines.append("## References")
            for cwe in finding.cwe_ids:
                lines.append(f"- {cwe}")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def to_api_payload(
        finding: Any,
        program_handle: str = "",
    ) -> dict[str, Any]:
        """
        HackerOne API v1 submission payload oluştur.

        Returns:
            HackerOne /reports endpoint'ine gönderilebilecek dict
        """
        sev = SEVERITY_RATINGS.get(
            getattr(finding.severity, "value", str(finding.severity or "medium")), SEVERITY_RATINGS["medium"]
        )
        weakness = WEAKNESS_MAP.get(
            finding.vulnerability_type,
            {"id": 75, "name": "Other"}
        )

        markdown_body = HackerOneTemplate.format_finding(finding)

        payload: dict[str, Any] = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": finding.title,
                    "vulnerability_information": markdown_body,
                    "impact": finding.impact or _default_impact(finding.vulnerability_type),
                    "severity_rating": sev["rating"],
                },
                "relationships": {
                    "weakness": {
                        "data": {
                            "type": "weakness",
                            "id": weakness["id"],
                        }
                    },
                },
            },
        }

        if program_handle:
            payload["data"]["relationships"]["program"] = {
                "data": {
                    "type": "program",
                    "id": program_handle,
                }
            }

        # Structured scopes
        if finding.endpoint:
            payload["data"]["relationships"]["structured_scope"] = {
                "data": {
                    "type": "structured-scope",
                    "attributes": {
                        "asset_identifier": finding.target or finding.endpoint,
                        "asset_type": "URL",
                    },
                }
            }

        return payload

    @staticmethod
    def format_full_report(report: Any) -> str:
        """
        Birden fazla bulgu içeren tam HackerOne raporu oluştur.

        Her bulgu ayrı bir rapor olarak gönderilse de,
        executive summary ile birleşik rapor da üretilebilir.
        """
        lines: list[str] = []

        lines.append(f"# Security Assessment: {report.target}")
        lines.append(f"\n**Program:** {report.program_name or 'N/A'}")
        lines.append(
            f"**Date:** {__import__('time').strftime('%Y-%m-%d', __import__('time').gmtime(report.generated_at))}"
        )
        lines.append(f"**Findings:** {report.finding_count}")
        lines.append("\n---\n")

        lines.append("## Executive Summary\n")
        lines.append(report.executive_summary or "See individual findings below.")
        lines.append("\n---\n")

        for i, finding in enumerate(report.findings, 1):
            lines.append(f"# Finding {i}: {finding.title}\n")
            lines.append(HackerOneTemplate.format_finding(finding))
            lines.append(f"\n{'='*60}\n")

        return "\n".join(lines)


def _default_impact(vuln_type: str) -> str:
    """Zafiyet türüne göre varsayılan etki analizi."""
    IMPACTS = {
        "sql_injection": (
            "An attacker could exploit this SQL injection vulnerability to extract "
            "sensitive data from the database, including user credentials, personal "
            "information, and business-critical data. In severe cases, this could lead "
            "to full database compromise, data manipulation, or even remote code "
            "execution on the database server."
        ),
        "command_injection": (
            "An attacker could execute arbitrary operating system commands on the "
            "server, potentially leading to full system compromise, data exfiltration, "
            "lateral movement within the network, and installation of backdoors."
        ),
        "xss_reflected": (
            "An attacker could use this reflected XSS to steal session tokens, "
            "perform actions on behalf of authenticated users, redirect victims to "
            "malicious sites, or deface the web application."
        ),
        "xss_stored": (
            "An attacker could use this stored XSS vulnerability to persistently "
            "attack any user who visits the affected page. This can lead to mass "
            "session hijacking, credential theft, and worm-like propagation."
        ),
        "ssrf": (
            "An attacker could exploit this SSRF vulnerability to access internal "
            "services, scan internal networks, read local files, or interact with "
            "cloud metadata endpoints (e.g., AWS IMDSv1) to escalate privileges."
        ),
        "ssti": (
            "An attacker could exploit this server-side template injection to "
            "achieve remote code execution on the server, leading to full system "
            "compromise and data breach."
        ),
        "idor": (
            "An attacker could access or modify other users' data by manipulating "
            "object references, potentially compromising user privacy and data "
            "integrity at scale."
        ),
        "authentication_bypass": (
            "An attacker could bypass authentication mechanisms to gain unauthorized "
            "access to protected resources, potentially accessing other users' "
            "accounts or administrative functionality."
        ),
        "cors_misconfiguration": (
            "An attacker could exploit the CORS misconfiguration to steal sensitive "
            "data from authenticated users by making cross-origin requests from a "
            "malicious website."
        ),
        "open_redirect": (
            "An attacker could use this open redirect to redirect users to a "
            "phishing page, potentially stealing credentials or facilitating "
            "further social engineering attacks."
        ),
    }
    return IMPACTS.get(vuln_type, (
        "This vulnerability could be exploited by an attacker to compromise "
        "the security of the application and its users."
    ))


__all__ = ["HackerOneTemplate", "SEVERITY_RATINGS", "WEAKNESS_MAP"]
