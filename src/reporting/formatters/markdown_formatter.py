"""
WhiteHatHacker AI — Markdown Report Formatter

Zafiyet raporlarını Markdown formatında oluşturur.
HackerOne/Bugcrowd uyumlu çıktı üretir.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


class MarkdownSection(BaseModel):
    """Rapor bölümü."""

    heading: str = ""
    level: int = 2
    content: str = ""
    subsections: list["MarkdownSection"] = Field(default_factory=list)

    def render(self) -> str:
        prefix = "#" * self.level
        lines: list[str] = []

        if self.heading:
            lines.append(f"{prefix} {self.heading}")
            lines.append("")

        if self.content:
            lines.append(self.content)
            lines.append("")

        for sub in self.subsections:
            lines.append(sub.render())

        return "\n".join(lines)


class MarkdownFormatter:
    """
    Markdown report formatter.

    Usage:
        fmt = MarkdownFormatter()
        md = fmt.format_report(report_data)
        fmt.save(md, "output/reports/finding_001.md")
    """

    def format_report(self, report: dict[str, Any]) -> str:
        """Tam rapor formatla."""
        sections: list[str] = []

        # Başlık
        title = report.get("title", "Security Finding Report")
        sections.append(f"# {title}")
        sections.append("")

        # Meta
        meta = report.get("meta", {})
        if meta:
            sections.append(self._format_meta(meta))

        # Summary
        summary = report.get("summary", "")
        if summary:
            sections.append("## Summary")
            sections.append("")
            sections.append(summary)
            sections.append("")

        # Severity
        severity = report.get("severity", {})
        if severity:
            sections.append(self._format_severity(severity))

        # Steps to Reproduce
        steps = report.get("steps_to_reproduce", [])
        if steps:
            sections.append(self._format_steps(steps))

        # Impact
        impact = report.get("impact", "")
        if impact:
            sections.append("## Impact")
            sections.append("")
            sections.append(impact)
            sections.append("")

        # Proof of Concept
        poc = report.get("poc", {})
        if poc:
            sections.append(self._format_poc(poc))

        # HTTP Evidence
        http_evidence = report.get("http_evidence", [])
        if http_evidence:
            sections.append(self._format_http_evidence(http_evidence))

        # Screenshots
        screenshots = report.get("screenshots", [])
        if screenshots:
            sections.append(self._format_screenshots(screenshots))

        # Suggested Fix
        remediation = report.get("remediation", "")
        if remediation:
            sections.append("## Suggested Fix")
            sections.append("")
            sections.append(remediation)
            sections.append("")

        # References
        references = report.get("references", [])
        if references:
            sections.append(self._format_references(references))

        # CVSS Detail
        cvss = report.get("cvss", {})
        if cvss:
            sections.append(self._format_cvss(cvss))

        return "\n".join(sections)

    def format_finding(self, finding: dict[str, Any]) -> str:
        """Tek bir bulgu formatla (kısa versiyon)."""
        lines: list[str] = []

        title = finding.get("title", "Untitled Finding")
        severity = str(finding.get("severity") or "medium")
        confidence = finding.get("confidence_score", finding.get("confidence", 0))

        lines.append(f"### {title}")
        lines.append("")
        lines.append(f"**Severity:** {severity.upper()} | **Confidence:** {confidence}%")
        lines.append("")

        if finding.get("url"):
            lines.append(f"**URL:** `{finding['url']}`")
            lines.append("")

        if finding.get("description"):
            lines.append(finding["description"])
            lines.append("")

        if finding.get("evidence"):
            lines.append("**Evidence:**")
            lines.append(f"```\n{finding['evidence']}\n```")
            lines.append("")

        return "\n".join(lines)

    def format_findings_summary(
        self,
        findings: list[dict[str, Any]],
        session_id: str = "",
    ) -> str:
        """Tüm bulguların özet tablosu."""
        lines: list[str] = []

        lines.append("# Findings Summary")
        lines.append("")

        if session_id:
            lines.append(f"**Session:** `{session_id}`")
            lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            lines.append("")

        # Tablo
        lines.append("| # | Severity | Title | Confidence | Status |")
        lines.append("|---|----------|-------|------------|--------|")

        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity") or "unknown").upper()
            title = f.get("title", "Untitled")[:60]
            conf = f.get("confidence_score", f.get("confidence", 0))
            status = f.get("status", "unverified")
            lines.append(f"| {i} | {sev} | {title} | {conf}% | {status} |")

        lines.append("")

        # İstatistikler
        sev_counts: dict[str, int] = {}
        for f in findings:
            s = str(f.get("severity") or "unknown").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        lines.append("### Statistics")
        lines.append("")
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = sev_counts.get(sev, 0)
            if cnt:
                lines.append(f"- **{sev.upper()}:** {cnt}")

        lines.append(f"- **Total:** {len(findings)}")
        lines.append("")

        return "\n".join(lines)

    # --------- Private Helpers ---------

    def _format_meta(self, meta: dict[str, Any]) -> str:
        lines = [
            "| Field | Value |",
            "|-------|-------|",
        ]
        for k, v in meta.items():
            lines.append(f"| {k} | {v} |")
        lines.append("")
        return "\n".join(lines)

    def _format_severity(self, severity: dict[str, Any]) -> str:
        lines = ["## Severity", ""]

        score = severity.get("cvss_score", "N/A")
        label = severity.get("label", "N/A")
        vector = severity.get("vector", "")

        lines.append(f"**CVSS Score:** {score} ({label})")
        if vector:
            lines.append(f"**Vector:** `{vector}`")
        lines.append("")

        return "\n".join(lines)

    def _format_steps(self, steps: list[str | dict]) -> str:
        lines = ["## Steps to Reproduce", ""]

        for i, step in enumerate(steps, 1):
            if isinstance(step, str):
                lines.append(f"{i}. {step}")
            elif isinstance(step, dict):
                desc = step.get("description", "")
                lines.append(f"{i}. {desc}")
                if step.get("code"):
                    lines.append(f"   ```\n   {step['code']}\n   ```")

        lines.append("")
        return "\n".join(lines)

    def _format_poc(self, poc: dict[str, Any]) -> str:
        lines = ["## Proof of Concept", ""]

        if poc.get("description"):
            lines.append(poc["description"])
            lines.append("")

        if poc.get("code"):
            lang = poc.get("language", "")
            lines.append(f"```{lang}")
            lines.append(poc["code"])
            lines.append("```")
            lines.append("")

        if poc.get("command"):
            lines.append("```bash")
            lines.append(poc["command"])
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

    def _format_http_evidence(self, evidence: list[dict]) -> str:
        lines = ["## HTTP Evidence", ""]

        for i, ev in enumerate(evidence, 1):
            lines.append(f"### Request/Response #{i}")
            lines.append("")

            if ev.get("request"):
                lines.append("**Request:**")
                lines.append("```http")
                lines.append(ev["request"])
                lines.append("```")
                lines.append("")

            if ev.get("response"):
                lines.append("**Response:**")
                lines.append("```http")
                resp = ev["response"]
                # Truncate büyük response'lar
                if len(resp) > 2000:
                    resp = resp[:2000] + "\n... [truncated]"
                lines.append(resp)
                lines.append("```")
                lines.append("")

        return "\n".join(lines)

    def _format_screenshots(self, screenshots: list[str]) -> str:
        lines = ["## Screenshots", ""]
        for i, ss in enumerate(screenshots, 1):
            lines.append(f"![Screenshot {i}]({ss})")
            lines.append("")
        return "\n".join(lines)

    def _format_references(self, references: list[str | dict]) -> str:
        lines = ["## References", ""]
        for ref in references:
            if isinstance(ref, str):
                lines.append(f"- {ref}")
            elif isinstance(ref, dict):
                name = ref.get("name", ref.get("url", ""))
                url = ref.get("url", "")
                lines.append(f"- [{name}]({url})")
        lines.append("")
        return "\n".join(lines)

    def _format_cvss(self, cvss: dict[str, Any]) -> str:
        lines = ["## CVSS v3.1 Breakdown", ""]

        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")

        metrics = [
            ("Attack Vector", "AV"),
            ("Attack Complexity", "AC"),
            ("Privileges Required", "PR"),
            ("User Interaction", "UI"),
            ("Scope", "S"),
            ("Confidentiality", "C"),
            ("Integrity", "I"),
            ("Availability", "A"),
        ]

        for label, key in metrics:
            val = cvss.get(key, "N/A")
            lines.append(f"| {label} | {val} |")

        lines.append("")
        return "\n".join(lines)

    # --------- Save ---------

    def save(self, content: str, filepath: str) -> str:
        """Markdown dosyasına kaydet."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info(f"Markdown report saved: {path}")
        return str(path)


__all__ = [
    "MarkdownFormatter",
    "MarkdownSection",
]
