"""
WhiteHatHacker AI — Multi-Target Campaign Manager (P6-2)

Orchestrates scanning multiple targets sequentially with shared
KnowledgeBase context, campaign-level reporting, and consolidated
GlobalFindingStore tracking.

Usage (CLI):
    whai campaign --targets targets.txt --scope-dir config/scopes/ --profile balanced

Features:
- Reads target list from file (one target per line)
- Auto-matches scope files by domain name convention
- Shared KnowledgeBase → cross-target learning
- Campaign-level markdown summary report
- GlobalFindingStore dedup across all targets
- Graceful shutdown (SIGINT) between target scans
"""

from __future__ import annotations

import asyncio
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger


@dataclass
class TargetResult:
    """Outcome of scanning a single target."""

    target: str
    scan_id: str = ""
    status: str = "pending"  # pending | running | completed | failed | skipped
    duration_s: float = 0.0
    findings_total: int = 0
    findings_high_crit: int = 0
    error: str = ""
    started_at: str = ""
    finished_at: str = ""


@dataclass
class CampaignReport:
    """Aggregated campaign-level report."""

    campaign_id: str
    started_at: str
    finished_at: str = ""
    duration_s: float = 0.0
    targets_total: int = 0
    targets_completed: int = 0
    targets_failed: int = 0
    targets_skipped: int = 0
    total_findings: int = 0
    total_high_crit: int = 0
    results: list[TargetResult] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            f"# Campaign Report — {self.campaign_id}",
            "",
            f"**Started:** {self.started_at}  ",
            f"**Finished:** {self.finished_at}  ",
            f"**Duration:** {self.duration_s:.0f}s  ",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Targets Total | {self.targets_total} |",
            f"| Completed | {self.targets_completed} |",
            f"| Failed | {self.targets_failed} |",
            f"| Skipped | {self.targets_skipped} |",
            f"| Total Findings | {self.total_findings} |",
            f"| HIGH/CRITICAL | {self.total_high_crit} |",
            "",
            "## Per-Target Results",
            "",
            "| Target | Status | Duration | Findings | HIGH/CRIT | Error |",
            "|--------|--------|----------|----------|-----------|-------|",
        ]
        for r in self.results:
            err = r.error[:40] if r.error else ""
            lines.append(
                f"| {r.target} | {r.status} | {r.duration_s:.0f}s "
                f"| {r.findings_total} | {r.findings_high_crit} | {err} |"
            )
        lines.append("")
        return "\n".join(lines)


class CampaignManager:
    """
    Manages a multi-target scanning campaign.

    Scans targets sequentially (not in parallel, to respect rate limits
    and avoid resource exhaustion). Cross-target learning happens through
    a shared KnowledgeBase.
    """

    def __init__(
        self,
        targets: list[str],
        scope_dir: str | Path | None = None,
        profile: str = "balanced",
        mode: str = "autonomous",
        config_path: str = "config/settings.yaml",
        output_dir: str = "output",
        no_brain: bool = False,
        incremental: bool = False,
    ):
        self.targets = [t.strip() for t in targets if t.strip() and not t.strip().startswith("#")]
        self.scope_dir = Path(scope_dir) if scope_dir else None
        self.profile = profile
        self.mode = mode
        self.config_path = config_path
        self.output_dir = Path(output_dir)
        self.no_brain = no_brain
        self.incremental = incremental

        self._stop_event = asyncio.Event()
        self._campaign_id = datetime.now(timezone.utc).strftime("campaign_%Y%m%d_%H%M%S")
        self._results: list[TargetResult] = []

    @classmethod
    def from_file(
        cls,
        targets_file: str | Path,
        **kwargs: Any,
    ) -> CampaignManager:
        """Create campaign from a targets file (one per line)."""
        path = Path(targets_file)
        if not path.exists():
            raise FileNotFoundError(f"Targets file not found: {path}")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        targets = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        if not targets:
            raise ValueError(f"No targets found in {path}")
        return cls(targets=targets, **kwargs)

    def _find_scope_file(self, target: str) -> Path | None:
        """Try to auto-match a scope YAML by target domain."""
        if not self.scope_dir or not self.scope_dir.is_dir():
            return None

        # Try exact match: example.com → example_com.yaml or example.com.yaml
        domain = target.split("://")[-1].split("/")[0].split(":")[0]
        candidates = [
            domain.replace(".", "_") + ".yaml",
            domain.replace(".", "_") + ".yml",
            domain + ".yaml",
            domain + ".yml",
        ]
        # Also try without TLD: example_com → example
        parts = domain.split(".")
        if len(parts) >= 2:
            base = parts[-2]
            candidates.extend([f"{base}.yaml", f"{base}.yml"])

        for name in candidates:
            p = self.scope_dir / name
            if p.exists():
                return p
        return None

    def _load_scope(self, scope_file: Path | None) -> dict[str, Any] | None:
        """Load a scope YAML file."""
        if not scope_file or not scope_file.exists():
            return None
        try:
            import yaml

            return yaml.safe_load(scope_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning(f"Failed to load scope {scope_file}: {exc}")
            return None

    async def run(self) -> CampaignReport:
        """Execute the campaign — scan all targets sequentially."""
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._signal_handler)
            except (NotImplementedError, RuntimeError):
                pass  # Not supported on all platforms

        report = CampaignReport(
            campaign_id=self._campaign_id,
            started_at=datetime.now(timezone.utc).isoformat(),
            targets_total=len(self.targets),
        )

        logger.info(
            f"Campaign {self._campaign_id} starting — "
            f"{len(self.targets)} targets, profile={self.profile}"
        )

        t0 = time.monotonic()

        for idx, target in enumerate(self.targets, 1):
            if self._stop_event.is_set():
                remaining = len(self.targets) - idx + 1
                logger.warning(f"Campaign stopped by signal. {remaining} targets skipped.")
                for t in self.targets[idx - 1 :]:
                    self._results.append(TargetResult(target=t, status="skipped"))
                    report.targets_skipped += 1
                break

            logger.info(f"[{idx}/{len(self.targets)}] Scanning target: {target}")
            result = await self._scan_target(target)
            self._results.append(result)

            if result.status == "completed":
                report.targets_completed += 1
            else:
                report.targets_failed += 1

            report.total_findings += result.findings_total
            report.total_high_crit += result.findings_high_crit

        report.duration_s = time.monotonic() - t0
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.results = list(self._results)

        # Save campaign report
        report_dir = self.output_dir / "campaigns"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"{self._campaign_id}.md"
        report_path.write_text(report.to_markdown(), encoding="utf-8")
        logger.info(f"Campaign report saved: {report_path}")

        return report

    async def _scan_target(self, target: str) -> TargetResult:
        """Run a single target scan."""
        result = TargetResult(
            target=target,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        t0 = time.monotonic()

        try:
            scope_file = self._find_scope_file(target)
            scope = self._load_scope(scope_file)

            # Import here to avoid circular
            from src.main import run_scan

            state = await run_scan(
                target=target,
                scope=scope,
                config_path=self.config_path,
                mode_override=self.mode,
                profile_override=self.profile,
                allow_no_brain=self.no_brain,
                incremental=self.incremental,
            )

            result.status = "completed"
            result.scan_id = getattr(state, "session_id", "")

            # Extract findings from state (WorkflowState uses verified_findings)
            findings = []
            if hasattr(state, "verified_findings") and state.verified_findings:
                findings = state.verified_findings
            elif hasattr(state, "raw_findings") and state.raw_findings:
                findings = state.raw_findings

            result.findings_total = len(findings)
            for f in findings:
                sev = ""
                if isinstance(f, dict):
                    sev = (f.get("severity") or "").lower()
                elif hasattr(f, "severity"):
                    sev = (getattr(f, "severity", "") or "").lower()
                if sev in ("high", "critical"):
                    result.findings_high_crit += 1

        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)[:200]
            logger.error(f"Campaign target {target} failed: {exc}")

        result.duration_s = time.monotonic() - t0
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result

    def _signal_handler(self) -> None:
        logger.warning("Campaign received stop signal — finishing current target then stopping")
        self._stop_event.set()

    @property
    def campaign_id(self) -> str:
        return self._campaign_id

    @property
    def results(self) -> list[TargetResult]:
        return list(self._results)
