"""
WhiteHatHacker AI — Diff Engine (V7-T3-1)

İki scan sonucunu karşılaştırır (asset + finding seviyesinde):
  - Yeni / kaybolmuş subdomain'ler
  - Yeni / kaybolmuş endpoint'ler
  - Yeni / düzelen zafiyetler
  - Teknoloji değişiklikleri
  - Markdown diff raporu oluşturma

Bağımlılık: Asset DB (V7-T0-2)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from loguru import logger

from src.integrations.asset_db import AssetDB, AssetDiff


class ScanDiffReport:
    """Holds a structured diff between two scans."""

    def __init__(
        self,
        program_id: str,
        old_scan_id: str,
        new_scan_id: str,
        asset_diff: AssetDiff | None = None,
        new_findings: list[dict[str, Any]] | None = None,
        resolved_findings: list[dict[str, Any]] | None = None,
        tech_changes: list[dict[str, Any]] | None = None,
    ) -> None:
        self.program_id = program_id
        self.old_scan_id = old_scan_id
        self.new_scan_id = new_scan_id
        self.asset_diff = asset_diff
        self.new_findings = new_findings or []
        self.resolved_findings = resolved_findings or []
        self.tech_changes = tech_changes or []


class DiffEngine:
    """
    Compare two scans using the Asset DB and generate a structured report.
    """

    def __init__(self, db: AssetDB) -> None:
        self._db = db

    def diff(
        self,
        program_id: str,
        old_scan_id: str,
        new_scan_id: str,
    ) -> ScanDiffReport:
        """Generate a full diff between two scan runs."""
        # Asset diff
        asset_diff = self._db.diff_assets(program_id, old_scan_id, new_scan_id)

        # Finding diff — compare finding_history records
        new_findings = self._find_new_findings(program_id, old_scan_id, new_scan_id)
        resolved_findings = self._find_resolved_findings(program_id, old_scan_id, new_scan_id)

        return ScanDiffReport(
            program_id=program_id,
            old_scan_id=old_scan_id,
            new_scan_id=new_scan_id,
            asset_diff=asset_diff,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
        )

    def _find_new_findings(
        self, program_id: str, old_scan_id: str, new_scan_id: str,
    ) -> list[dict[str, Any]]:
        """Findings present in new scan but not in old scan.

        A finding is 'new' if its first_found timestamp is ON or AFTER
        the new scan started, meaning it was first discovered in this scan
        (not in any prior scan).
        """
        all_findings = self._db.get_findings(program_id)
        new_scan_start = self._get_scan_start(program_id, new_scan_id)
        if new_scan_start:
            return [
                f for f in all_findings
                if f.get("first_found", "") >= new_scan_start
                and f.get("status") != "fixed"
            ]
        # Fallback: findings whose scan_id matches new and were never seen before
        return [
            f for f in all_findings
            if f.get("first_found", "") == f.get("last_found", "")
            and f.get("scan_id") == new_scan_id
        ]

    def _find_resolved_findings(
        self, program_id: str, old_scan_id: str, new_scan_id: str,
    ) -> list[dict[str, Any]]:
        """Findings present in old scan but not re-confirmed in new scan.

        A finding is 'resolved' if its last_found timestamp is BEFORE
        the new scan started (i.e., it wasn't re-seen).
        """
        all_findings = self._db.get_findings(program_id)
        new_scan_start = self._get_scan_start(program_id, new_scan_id)
        if not new_scan_start:
            return []
        return [
            f for f in all_findings
            if f.get("last_found", "") < new_scan_start
            and f.get("status") != "fixed"
        ]

    def _get_scan_start(self, program_id: str, scan_id: str) -> str:
        """Return started_at ISO timestamp for a scan, or ''."""
        runs = self._db.get_scan_runs(program_id)
        for r in runs:
            if r.get("id") == scan_id:
                return r.get("started_at", "")
        return ""

    def generate_markdown(self, report: ScanDiffReport) -> str:
        """Generate a Markdown diff report."""
        lines: list[str] = []
        lines.append(f"# Scan Diff Report")
        lines.append(f"**{report.old_scan_id}** → **{report.new_scan_id}**")
        lines.append(f"**Program:** {report.program_id}")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
        lines.append("")

        # Asset diff
        ad = report.asset_diff
        if ad:
            if ad.new_assets:
                lines.append(f"## New Assets ({len(ad.new_assets)})")
                for a in ad.new_assets:
                    lines.append(f"- **[NEW]** `{a.value}` ({a.asset_type})")
                lines.append("")

            if ad.disappeared_assets:
                lines.append(f"## Disappeared Assets ({len(ad.disappeared_assets)})")
                for a in ad.disappeared_assets:
                    lines.append(f"- **[GONE]** `{a.value}` ({a.asset_type})")
                lines.append("")

            if not ad.new_assets and not ad.disappeared_assets:
                lines.append("## Assets\nNo changes.\n")

        # New findings
        if report.new_findings:
            lines.append(f"## New Findings ({len(report.new_findings)})")
            for f in report.new_findings:
                sev = str(f.get("severity") or "UNKNOWN").upper()
                title = f.get("title", f.get("vuln_type", "Unknown"))
                asset = f.get("asset_value", "")
                lines.append(f"- **[NEW]** {sev}: {title} ({asset})")
            lines.append("")
        else:
            lines.append("## Findings\nNo new findings.\n")

        # Resolved findings
        if report.resolved_findings:
            lines.append(f"## Resolved Findings ({len(report.resolved_findings)})")
            for f in report.resolved_findings:
                sev = str(f.get("severity") or "UNKNOWN").upper()
                title = f.get("title", f.get("vuln_type", "Unknown"))
                lines.append(f"- **[FIXED]** {sev}: {title}")
            lines.append("")

        return "\n".join(lines)
