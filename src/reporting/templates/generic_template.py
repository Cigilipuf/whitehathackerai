"""
WhiteHatHacker AI — Generic Report Template

Platform-agnostic rapor formatı. Herhangi bir bug bounty platformuna
veya internal güvenlik raporlamasına uyumludur.
"""

from __future__ import annotations

import time
from typing import Any



class GenericTemplate:
    """
    Platform bağımsız, kapsamlı güvenlik raporu şablonu.

    İç güvenlik değerlendirmeleri, penetrasyon testi çıktıları
    ve platform-agnostic raporlama için kullanılır.
    """

    @staticmethod
    def format_finding(finding: Any) -> str:
        """Tek bir bulguyu generic Markdown formatında oluştur."""
        lines: list[str] = []

        # ── Header ────────────────────────────────────────────
        sev = getattr(finding.severity, "value", str(finding.severity or "info")).upper()
        lines.append(f"## [{sev}] {finding.title}")
        lines.append("")

        # ── Overview Table ────────────────────────────────────
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| **Severity** | {sev} |")
        lines.append(f"| **CVSS Score** | {finding.cvss_score} |")
        lines.append(f"| **CVSS Vector** | `{finding.cvss_vector}` |")
        lines.append(f"| **Type** | {(finding.vulnerability_type or 'unknown').replace('_', ' ').title()} |")
        if finding.cwe_ids:
            lines.append(f"| **CWE** | {', '.join(finding.cwe_ids)} |")
        lines.append(f"| **Confidence** | {finding.confidence_score or 0:.0f}% |")
        lines.append(f"| **Endpoint** | `{finding.endpoint}` |")
        if finding.parameter:
            lines.append(f"| **Parameter** | `{finding.parameter}` |")
        if finding.tool_sources:
            lines.append(f"| **Detected By** | {', '.join(finding.tool_sources)} |")
        lines.append("")

        # ── Description ──────────────────────────────────────
        lines.append("### Description")
        if finding.summary:
            lines.append(finding.summary)
        elif finding.description:
            lines.append(finding.description)
        else:
            lines.append(
                f"A {(finding.vulnerability_type or 'unknown').replace('_', ' ')} vulnerability "
                f"was identified in the target application."
            )
        lines.append("")

        # ── Impact Analysis ──────────────────────────────────
        lines.append("### Impact Analysis")
        if finding.impact:
            lines.append(finding.impact)
        else:
            lines.append(
                "This vulnerability could potentially be exploited by an attacker "
                "to compromise the security posture of the application."
            )
        lines.append("")

        # ── Reproduction Steps ────────────────────────────────
        lines.append("### Steps to Reproduce")
        if finding.steps_to_reproduce:
            lines.append("")
            for i, step in enumerate(finding.steps_to_reproduce, 1):
                lines.append(f"{i}. {step}")
        else:
            lines.append("")
            lines.append("1. Access the target endpoint")
            if finding.endpoint:
                lines.append(f"2. URL: `{finding.endpoint}`")
            if finding.parameter:
                lines.append(
                    f"3. Inject payload into `{finding.parameter}` parameter"
                )
            if finding.payload:
                lines.append(f"4. Payload: `{finding.payload}`")
            lines.append("5. Observe the vulnerability in the response")
        lines.append("")

        # ── Technical Evidence ────────────────────────────────
        has_evidence = (
            finding.http_request or finding.http_response
            or finding.poc_code or finding.evidence
        )

        if has_evidence:
            lines.append("### Technical Evidence")
            lines.append("")

            if finding.http_request:
                lines.append("**HTTP Request:**")
                lines.append(f"```http\n{finding.http_request[:4000]}\n```")
                lines.append("")

            if finding.http_response:
                resp = finding.http_response
                if len(resp) > 3000:
                    resp = resp[:3000] + "\n... [response truncated]"
                lines.append("**HTTP Response:**")
                lines.append(f"```http\n{resp}\n```")
                lines.append("")

            if finding.poc_code:
                lines.append("**Proof of Concept:**")
                lines.append(f"```\n{finding.poc_code[:3000]}\n```")
                lines.append("")

            if finding.evidence:
                lines.append("**Additional Evidence:**")
                for ev in finding.evidence:
                    if isinstance(ev, str):
                        lines.append(f"- {ev}")
                lines.append("")

        # ── Screenshots ──────────────────────────────────────
        screenshots = getattr(finding, "screenshots", [])
        if screenshots:
            lines.append("### Screenshots")
            for i, ss in enumerate(screenshots, 1):
                lines.append(f"\n![Evidence {i}]({ss})")
            lines.append("")

        # ── Remediation ──────────────────────────────────────
        lines.append("### Recommended Remediation")
        if finding.remediation:
            lines.append(finding.remediation)
        else:
            lines.append(
                "Address the identified vulnerability following industry best practices "
                "and security guidelines."
            )
        lines.append("")

        # ── References ────────────────────────────────────────
        if finding.references or finding.cwe_ids:
            lines.append("### References")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def format_full_report(report: Any) -> str:
        """
        Tam generic güvenlik değerlendirme raporu oluştur.

        Profesyonel penetrasyon testi raporu formatında:
        Cover → Executive Summary → Methodology → Findings → Appendix
        """
        lines: list[str] = []

        # ══════════════════════════════════════════════════════
        # COVER PAGE
        # ══════════════════════════════════════════════════════
        lines.append("# Security Assessment Report")
        lines.append(f"## Target: {report.target}")
        lines.append("")
        lines.append("| Detail | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Date** | {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(report.generated_at))} |")
        lines.append(f"| **Report ID** | `{report.report_id}` |")
        if report.program_name:
            lines.append(f"| **Program** | {report.program_name} |")
        lines.append(f"| **Session** | `{report.session_id}` |")
        lines.append(f"| **Duration** | {report.total_scan_time:.0f} seconds |")
        lines.append(f"| **Findings** | {report.finding_count} |")
        lines.append("")

        # Severity overview
        sev_counts: dict[str, int] = {}
        for f in report.findings:
            s = f.severity.value
            sev_counts[s] = sev_counts.get(s, 0) + 1

        lines.append("### Severity Distribution")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            lines.append(f"| {sev.upper()} | {count} |")
        lines.append("")

        # ══════════════════════════════════════════════════════
        # EXECUTIVE SUMMARY
        # ══════════════════════════════════════════════════════
        lines.append("---")
        lines.append("")
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(report.executive_summary or "See findings section for details.")
        lines.append("")

        # ══════════════════════════════════════════════════════
        # METHODOLOGY
        # ══════════════════════════════════════════════════════
        lines.append("## 2. Methodology")
        lines.append("")
        lines.append(
            "This assessment was conducted using an automated security analysis "
            "framework combining multiple security tools with AI-powered analysis. "
            "The methodology follows the OWASP Testing Guide and industry standard "
            "penetration testing methodologies."
        )
        lines.append("")
        lines.append("**Phases:**")
        lines.append("1. Passive Reconnaissance")
        lines.append("2. Active Reconnaissance")
        lines.append("3. Enumeration & Attack Surface Mapping")
        lines.append("4. Vulnerability Scanning")
        lines.append("5. False Positive Elimination (AI-assisted)")
        lines.append("6. Manual Verification & Reporting")
        lines.append("")

        if report.tools_used:
            lines.append("**Tools Used:**")
            for tool in report.tools_used:
                lines.append(f"- {tool}")
            lines.append("")

        # ══════════════════════════════════════════════════════
        # FINDINGS
        # ══════════════════════════════════════════════════════
        lines.append("---")
        lines.append("")
        lines.append("## 3. Detailed Findings")
        lines.append("")

        if not report.findings:
            lines.append("*No vulnerabilities were identified during this assessment.*")
        else:
            # Finding summary table
            lines.append("### 3.1 Finding Summary")
            lines.append("")
            lines.append("| # | Title | Severity | CVSS | Type |")
            lines.append("|---|-------|----------|------|------|")
            for i, f in enumerate(report.findings, 1):
                lines.append(
                    f"| {i} | {f.title} | {f.severity.value.upper()} | "
                    f"{f.cvss_score} | {f.vulnerability_type.replace('_', ' ').title()} |"
                )
            lines.append("")

            # Individual findings
            lines.append("### 3.2 Finding Details")
            lines.append("")

            for i, finding in enumerate(report.findings, 1):
                lines.append(f"### Finding {i}")
                lines.append("")
                lines.append(GenericTemplate.format_finding(finding))
                lines.append("\n---\n")

        # ══════════════════════════════════════════════════════
        # CONCLUSION
        # ══════════════════════════════════════════════════════
        lines.append("## 4. Conclusion")
        lines.append("")

        if report.critical_count > 0 or report.high_count > 0:
            lines.append(
                "The assessment identified **critical and/or high severity** "
                "vulnerabilities that require immediate attention. It is strongly "
                "recommended to prioritize remediation of these issues before "
                "addressing lower severity findings."
            )
        elif report.finding_count > 0:
            lines.append(
                "The assessment identified security findings that should be "
                "addressed to improve the overall security posture of the "
                "application."
            )
        else:
            lines.append(
                "No significant vulnerabilities were identified during this "
                "assessment. However, this does not guarantee the absence of "
                "all security issues."
            )
        lines.append("")

        # ══════════════════════════════════════════════════════
        # FOOTER
        # ══════════════════════════════════════════════════════
        lines.append("---")
        lines.append("")
        lines.append(
            "*This report was generated by WhiteHatHacker AI v2.1 — "
            "Autonomous Bug Bounty Hunter Bot*"
        )
        lines.append(f"*Session ID: {report.session_id}*")

        return "\n".join(lines)


__all__ = ["GenericTemplate"]
