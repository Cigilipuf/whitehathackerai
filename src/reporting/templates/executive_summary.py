"""WhiteHatHacker AI — Executive Summary Report Template.

Generates a high-level, non-technical executive summary suitable for
management stakeholders and programme triagers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ExecutiveFinding(BaseModel):
    """Simplified finding for exec summary."""

    title: str
    severity: str
    business_impact: str
    status: str = "confirmed"
    remediation_urgency: str = "planned"


class ExecutiveSummary(BaseModel):
    """Structured executive summary."""

    programme_name: str = ""
    target: str = ""
    assessment_date: str = ""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    overall_risk: str = "low"
    key_findings: list[ExecutiveFinding] = Field(default_factory=list)
    summary_text: str = ""
    recommendations: list[str] = Field(default_factory=list)
    methodology_summary: str = ""
    scope_summary: str = ""
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ExecutiveSummaryTemplate:
    """Generate executive-level summary reports."""

    def generate(
        self,
        findings: list[dict[str, Any]],
        *,
        target: str = "",
        programme_name: str = "",
        scope: str = "",
    ) -> ExecutiveSummary:
        """Build an executive summary from raw findings."""
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        key_findings: list[ExecutiveFinding] = []

        for f in findings:
            sev = str(f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

            if sev in ("critical", "high"):
                key_findings.append(ExecutiveFinding(
                    title=f.get("title", "Unnamed finding"),
                    severity=sev,
                    business_impact=f.get("business_impact", "Potential data breach"),
                    status=f.get("status", "confirmed"),
                    remediation_urgency="immediate" if sev == "critical" else "next-sprint",
                ))

        overall_risk = self._calculate_overall_risk(sev_counts)
        summary_text = self._build_summary_text(target, sev_counts, overall_risk)
        recommendations = self._build_recommendations(sev_counts, findings)

        report = ExecutiveSummary(
            programme_name=programme_name,
            target=target,
            assessment_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            total_findings=len(findings),
            critical_count=sev_counts["critical"],
            high_count=sev_counts["high"],
            medium_count=sev_counts["medium"],
            low_count=sev_counts["low"],
            info_count=sev_counts["info"],
            overall_risk=overall_risk,
            key_findings=key_findings,
            summary_text=summary_text,
            recommendations=recommendations,
            methodology_summary=(
                "Automated and manual security assessment using industry-standard tools "
                "including vulnerability scanners, fuzzers, and custom checks with "
                "AI-assisted false positive elimination."
            ),
            scope_summary=scope or f"Target: {target}",
        )

        logger.info(
            f"Executive summary: {len(findings)} findings, "
            f"overall risk={overall_risk}"
        )
        return report

    def render_markdown(self, summary: ExecutiveSummary) -> str:
        """Render the executive summary as Markdown."""
        lines = [
            "# Executive Security Assessment Summary",
            "",
            f"**Programme:** {summary.programme_name or 'N/A'}",
            f"**Target:** {summary.target}",
            f"**Date:** {summary.assessment_date}",
            f"**Overall Risk Level:** **{summary.overall_risk.upper()}**",
            "",
            "---",
            "",
            "## Overview",
            "",
            summary.summary_text,
            "",
            "## Findings Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {summary.critical_count} |",
            f"| High | {summary.high_count} |",
            f"| Medium | {summary.medium_count} |",
            f"| Low | {summary.low_count} |",
            f"| Info | {summary.info_count} |",
            f"| **Total** | **{summary.total_findings}** |",
            "",
        ]

        if summary.key_findings:
            lines.extend(["## Key Findings", ""])
            for i, kf in enumerate(summary.key_findings, 1):
                lines.extend([
                    f"### {i}. {kf.title}",
                    f"- **Severity:** {kf.severity.upper()}",
                    f"- **Business Impact:** {kf.business_impact}",
                    f"- **Remediation Urgency:** {kf.remediation_urgency}",
                    "",
                ])

        if summary.recommendations:
            lines.extend(["## Recommendations", ""])
            for r in summary.recommendations:
                lines.append(f"- {r}")
            lines.append("")

        lines.extend([
            "## Methodology",
            "",
            summary.methodology_summary,
            "",
            "## Scope",
            "",
            summary.scope_summary,
            "",
            "---",
            f"*Generated: {summary.generated_at}*",
        ])

        return "\n".join(lines)

    # ---- Helpers ---------------------------------------------------------

    @staticmethod
    def _calculate_overall_risk(counts: dict[str, int]) -> str:
        if counts.get("critical", 0) > 0:
            return "critical"
        if counts.get("high", 0) > 0:
            return "high"
        if counts.get("medium", 0) > 0:
            return "medium"
        if counts.get("low", 0) > 0:
            return "low"
        return "info"

    @staticmethod
    def _build_summary_text(
        target: str, counts: dict[str, int], overall: str
    ) -> str:
        total = sum(counts.values())
        return (
            f"A comprehensive security assessment of **{target or 'the target'}** "
            f"identified **{total} finding(s)** across all severity levels. "
            f"The overall risk level is assessed as **{overall.upper()}**. "
            f"Critical findings: {counts['critical']}, High: {counts['high']}, "
            f"Medium: {counts['medium']}, Low: {counts['low']}, Informational: {counts['info']}."
        )

    @staticmethod
    def _build_recommendations(
        counts: dict[str, int], findings: list[dict[str, Any]]
    ) -> list[str]:
        recs: list[str] = []
        if counts.get("critical", 0) > 0:
            recs.append("IMMEDIATE: Remediate all critical findings within 24-48 hours")
        if counts.get("high", 0) > 0:
            recs.append("HIGH PRIORITY: Address high-severity findings within the current sprint")
        if counts.get("medium", 0) > 0:
            recs.append("Schedule medium-severity findings for remediation in the next release cycle")
        if counts.get("low", 0) > 0:
            recs.append("Include low-severity findings in backlog for opportunistic fixing")
        recs.append("Implement continuous security testing in the CI/CD pipeline")
        recs.append("Conduct security awareness training for the development team")
        return recs
